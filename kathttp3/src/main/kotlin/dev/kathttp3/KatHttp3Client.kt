package dev.kathttp3

import dev.kathttp3.internal.NativeBridge
import dev.kathttp3.internal.NativeCallback
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.receiveAsFlow
import java.io.ByteArrayOutputStream
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.launch
import java.io.FileInputStream

class KatHttp3Client(private val config: KatHttp3ClientConfig = KatHttp3ClientConfig(), applicationContext: android.content.Context? = null) : AutoCloseable {
    private val closed = AtomicBoolean(false)
    private val ids = AtomicLong(1)
    private val active = ConcurrentHashMap.newKeySet<Long>()
    private val requestScheduler = OriginRequestScheduler(
        config.maxActiveStreamsPerOrigin,
        config.maxQueuedRequestsPerOrigin,
        config.queueTimeoutMillis,
    )
    private val schedulerScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val nativeLock = Any()
    private val handle = NativeBridge.createClient(
        config.connectTimeoutMillis, config.requestTimeoutMillis, config.idleTimeoutMillis,
        config.dnsTimeoutMillis, config.handshakeTimeoutMillis,
        config.responseHeadersTimeoutMillis, config.readTimeoutMillis,
        config.writeTimeoutMillis, config.callTimeoutMillis, config.consumerStallTimeoutMillis, config.maxRedirects,
        config.trustMode.native, config.insecureCert, config.enableCookies, config.enable0Rtt, config.caCertificateFile,
        config.qlogPathPrefix, config.resolver,
    ).also { check(it != 0L) }
    private val networkMonitor = applicationContext?.let { AndroidNetworkMonitor(it) { generation -> synchronized(nativeLock) { if (!closed.get()) NativeBridge.networkChanged(handle, generation) } } }

    suspend fun execute(request: KatHttp3Request): KatHttp3Response {
        requestScheduler.acquire(request.url).use {
            return if (config.interceptors.isEmpty()) {
                executeReal(request)
            } else {
                InterceptorChainImpl(this, config.interceptors, 0, request).proceed()
            }
        }
    }

    internal suspend fun executeReal(request: KatHttp3Request): KatHttp3Response = suspendCancellableCoroutine { continuation ->
        if (closed.get()) { continuation.resumeWithException(KatHttp3Exception.Closed()); return@suspendCancellableCoroutine }
        val id = ids.getAndIncrement()
        val callback = BufferedCallback(id, continuation)
        active += id
        continuation.invokeOnCancellation { synchronized(nativeLock) { if (!closed.get()) NativeBridge.cancel(handle, id) }; active.remove(id) }
        val requestBody = request.streamingBody
        val bytes = (requestBody as? KatHttp3RequestBody.Bytes)?.value ?: request.body
        val streamingLength = when (requestBody) { is KatHttp3RequestBody.FileBody -> requestBody.file.length(); is KatHttp3RequestBody.Stream -> requestBody.contentLength ?: -1L; else -> -1L }
        val ok = synchronized(nativeLock) { if (closed.get()) false else NativeBridge.execute(handle, id, request.method, request.url, request.headers.map { it.name }.toTypedArray(), request.headers.map { it.value }.toTypedArray(), bytes, config.followRedirects, false, requestBody != null && requestBody !is KatHttp3RequestBody.Bytes, streamingLength, callback) }
        if (!ok) callback.fail(KatHttp3Exception.Native(-7))
        else if (requestBody != null && requestBody !is KatHttp3RequestBody.Bytes) startBodyProducer(id, requestBody, callback::fail)
    }

    fun executeStreaming(request: KatHttp3Request): KatHttp3Call {
        check(!closed.get()) { "Client is closed" }
        val id = ids.getAndIncrement()
        val permit = AtomicReference<OriginRequestScheduler.Permit?>(null)
        fun releasePermit() { permit.getAndSet(null)?.close() }
        val channel = Channel<KatHttp3StreamEvent>(capacity = 8)
        val stashLock = Any()
        val stash = ArrayDeque<ByteArray>()
        var stashedBytes = 0L
        val completePending = AtomicBoolean(false)
        fun drainOneStashedChunk() {
            val next = synchronized(stashLock) {
                if (stash.isEmpty()) null else stash.removeFirst().also { stashedBytes -= it.size }
            }
            if (next != null && !channel.trySend(KatHttp3StreamEvent.Body(next)).isSuccess) {
                synchronized(stashLock) { stash.addFirst(next); stashedBytes += next.size }
            }
        }
        fun finishIfDrained() {
            if (completePending.get() && synchronized(stashLock) { stash.isEmpty() }) channel.close()
        }
        lateinit var startJob: Job
        val call = KatHttp3Call(channel.receiveAsFlow()
            .onEach {
                if (it is KatHttp3StreamEvent.Body) {
                    // Credit is returned only after this Flow element has been
                    // delivered to the collector, never when native invokes a callback.
                    NativeBridge.consume(handle, id, it.bytes.size.toLong())
                    drainOneStashedChunk()
                    finishIfDrained()
                }
            }
        ) {
            startJob.cancel()
            synchronized(nativeLock) { if (!closed.get()) NativeBridge.cancel(handle, id) }
            releasePermit()
        }
        val terminal = AtomicBoolean(false)
        val callback = object : NativeCallback {
            override fun onHeaders(status: Int, names: Array<String>, values: Array<String>) { if (!channel.trySend(KatHttp3StreamEvent.Headers(status, names.indices.map { KatHttp3Header(names[it], values[it]) })).isSuccess) cancel() }
            override fun onBody(data: ByteArray) {
                if (channel.trySend(KatHttp3StreamEvent.Body(data)).isSuccess) return
                val overflow = synchronized(stashLock) {
                    if (stashedBytes + data.size > config.maxStreamingBufferedBodyBytes) true
                    else { stash.addLast(data); stashedBytes += data.size; false }
                }
                if (overflow) cancel()
            }
            override fun onComplete() { if (terminal.compareAndSet(false,true)) { active.remove(id); releasePermit(); completePending.set(true); finishIfDrained() } }
            override fun onError(code: Int) { fail(mapError(code)) }
            fun fail(error: Throwable) { if (terminal.compareAndSet(false,true)) { active.remove(id); releasePermit(); channel.close(error) } }
            fun cancel() { synchronized(nativeLock) { if (!closed.get()) NativeBridge.cancel(handle,id) }; onError(-6) }
        }
        val requestBody = request.streamingBody
        val bytes = (requestBody as? KatHttp3RequestBody.Bytes)?.value ?: request.body
        val streamingLength = when (requestBody) { is KatHttp3RequestBody.FileBody -> requestBody.file.length(); is KatHttp3RequestBody.Stream -> requestBody.contentLength ?: -1L; else -> -1L }
        startJob = schedulerScope.launch {
            try {
                permit.set(requestScheduler.acquire(request.url))
                if (closed.get()) {
                    callback.fail(KatHttp3Exception.Closed())
                    return@launch
                }
                active += id
                if (!synchronized(nativeLock) { if (closed.get()) false else NativeBridge.execute(handle,id,request.method,request.url,request.headers.map{it.name}.toTypedArray(),request.headers.map{it.value}.toTypedArray(),bytes,config.followRedirects,true,requestBody != null && requestBody !is KatHttp3RequestBody.Bytes,streamingLength,callback) }) callback.onError(-7)
                else if (requestBody != null && requestBody !is KatHttp3RequestBody.Bytes) startBodyProducer(id, requestBody) { callback.onError(-14) }
            } catch (t: Throwable) {
                callback.fail(t)
            }
        }
        return call
    }

    private fun startBodyProducer(id: Long, body: KatHttp3RequestBody, onFailure: (Throwable) -> Unit) {
        val source: Flow<ByteArray> = when (body) {
            is KatHttp3RequestBody.FileBody -> flow {
                FileInputStream(body.file).use { input ->
                    val buffer = ByteArray(16 * 1024)
                    while (true) { val read = input.read(buffer); if (read < 0) break; if (read > 0) emit(buffer.copyOf(read)) }
                }
            }
            is KatHttp3RequestBody.Stream -> body.source
            is KatHttp3RequestBody.Bytes -> return
        }
        CoroutineScope(Dispatchers.IO).launch {
            try {
                source.collect { chunk ->
                    require(chunk.isNotEmpty()) { "Streaming request body must not emit empty chunks" }
                    while (true) {
                        val result = NativeBridge.appendRequestBody(handle, id, chunk, false)
                        if (result == 0) break
                        if (result != -12) throw KatHttp3Exception.Native(result)
                        delay(5)
                    }
                }
                val result = NativeBridge.appendRequestBody(handle, id, null, true)
                if (result != 0) throw KatHttp3Exception.Native(result)
            } catch (t: Throwable) {
                synchronized(nativeLock) { if (!closed.get()) NativeBridge.cancel(handle, id) }
                onFailure(t)
            }
        }
    }

    private class InterceptorChainImpl(
        override val client: KatHttp3Client,
        private val interceptors: List<HttpInterceptor>,
        private val index: Int,
        override val request: KatHttp3Request,
    ) : InterceptorChain {
        override suspend fun proceed(request: KatHttp3Request): KatHttp3Response {
            return if (index < interceptors.size) {
                interceptors[index].intercept(InterceptorChainImpl(client, interceptors, index + 1, request))
            } else {
                client.executeReal(request)
            }
        }
    }

    override fun close() {
        synchronized(nativeLock) { if (!closed.compareAndSet(false, true)) return }
        NativeBridge.closeClient(handle)
        networkMonitor?.close()
        requestScheduler.close()
        schedulerScope.coroutineContext[Job]?.cancel()
        active.clear()
        NativeBridge.destroyClient(handle)
    }

    private inner class BufferedCallback(private val id: Long, private val continuation: CancellableContinuation<KatHttp3Response>) : NativeCallback {
        private val terminal = AtomicBoolean(false)
        private var status = 0
        private var headers = emptyList<KatHttp3Header>()
        private val body = ByteArrayOutputStream()
        override fun onHeaders(status: Int, names: Array<String>, values: Array<String>) { if (!terminal.get()) { this.status = status; headers = names.indices.map { KatHttp3Header(names[it], values[it]) } } }
        override fun onBody(data: ByteArray) {
            if (terminal.get()) return
            if (body.size().toLong() + data.size > config.maxBufferedBodyBytes) { synchronized(nativeLock) { if (!closed.get()) NativeBridge.cancel(handle, id) }; fail(KatHttp3Exception.BodyTooLarge()) } else body.write(data)
        }
        override fun onComplete() { if (terminal.compareAndSet(false, true)) { active.remove(id); if (continuation.isActive) {
            val resp = KatHttp3Response(status, headers, body.toByteArray())
            if (config.expectSuccess && resp.status >= 400) {
                continuation.resumeWithException(ResponseException(resp.status, "HTTP ${resp.status}", resp))
            } else {
                continuation.resume(resp)
            }
        } } }
        override fun onError(code: Int) = fail(mapError(code))
        fun fail(error: Throwable) { if (terminal.compareAndSet(false, true)) { active.remove(id); if (continuation.isActive) continuation.resumeWithException(error) } }
    }
}

sealed interface KatHttp3StreamEvent {
    data class Headers(val status: Int, val headers: List<KatHttp3Header>) : KatHttp3StreamEvent
    data class Body(val bytes: ByteArray) : KatHttp3StreamEvent
}

class KatHttp3Call internal constructor(val events: Flow<KatHttp3StreamEvent>, private val cancelAction: () -> Unit) : AutoCloseable {
    private val cancelled = AtomicBoolean(false)
    fun cancel() { if (cancelled.compareAndSet(false,true)) cancelAction() }
    override fun close() = cancel()
}

private fun mapError(code: Int): KatHttp3Exception = when (code) {
    -1 -> KatHttp3Exception.Dns()
    -3 -> QuicTransportException("QUIC transport error")
    -4 -> TlsHandshakeException("TLS handshake error")
    -5, -6, -7 -> CertificateVerificationException("Certificate verification failed (code $code)")
    -9 -> KatHttp3Exception.Timeout(KatHttp3TimeoutPhase.Call)
    -15 -> KatHttp3Exception.Timeout(KatHttp3TimeoutPhase.Dns)
    -16 -> KatHttp3Exception.Timeout(KatHttp3TimeoutPhase.Connect)
    -17 -> KatHttp3Exception.Timeout(KatHttp3TimeoutPhase.Handshake)
    -18 -> KatHttp3Exception.Timeout(KatHttp3TimeoutPhase.ResponseHeaders)
    -19 -> KatHttp3Exception.Timeout(KatHttp3TimeoutPhase.Read)
    -20 -> KatHttp3Exception.Timeout(KatHttp3TimeoutPhase.Write)
    -21 -> KatHttp3Exception.Timeout(KatHttp3TimeoutPhase.Call)
    -22 -> KatHttp3Exception.ConsumerStallTimeout()
    -13 -> KatHttp3Exception.Closed()
    else -> KatHttp3Exception.Native(code)
}

suspend fun KatHttp3Client.get(url: String, headers: List<KatHttp3Header> = emptyList()) = execute(KatHttp3Request("GET", url, headers))
suspend fun KatHttp3Client.post(url: String, body: ByteArray, headers: List<KatHttp3Header> = emptyList()) = execute(KatHttp3Request("POST", url, headers, body))
suspend fun KatHttp3Client.put(url: String, body: ByteArray, headers: List<KatHttp3Header> = emptyList()) = execute(KatHttp3Request("PUT", url, headers, body))
suspend fun KatHttp3Client.delete(url: String, headers: List<KatHttp3Header> = emptyList()) = execute(KatHttp3Request("DELETE", url, headers))
suspend fun KatHttp3Client.patch(url: String, body: ByteArray, headers: List<KatHttp3Header> = emptyList()) = execute(KatHttp3Request("PATCH", url, headers, body))
suspend fun KatHttp3Client.head(url: String, headers: List<KatHttp3Header> = emptyList()) = execute(KatHttp3Request("HEAD", url, headers))
