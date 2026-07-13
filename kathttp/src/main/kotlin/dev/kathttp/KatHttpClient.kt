package dev.kathttp

import dev.kathttp.internal.NativeBridge
import dev.kathttp.internal.NativeCallback
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.receiveAsFlow
import java.io.ByteArrayOutputStream
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

class KatHttpClient(private val config: KatHttpClientConfig = KatHttpClientConfig()) : AutoCloseable {
    private val closed = AtomicBoolean(false)
    private val ids = AtomicLong(1)
    private val active = ConcurrentHashMap.newKeySet<Long>()
    private val nativeLock = Any()
    private val handle = NativeBridge.createClient(
        config.connectTimeoutMillis, config.requestTimeoutMillis, config.idleTimeoutMillis,
        config.dnsTimeoutMillis, config.handshakeTimeoutMillis,
        config.responseHeadersTimeoutMillis, config.readTimeoutMillis,
        config.writeTimeoutMillis, config.callTimeoutMillis, config.maxRedirects,
        config.trustMode.native, config.insecureCert, config.caCertificateFile, config.resolver,
    ).also { check(it != 0L) }

    suspend fun execute(request: KatHttpRequest): KatHttpResponse {
        return if (config.interceptors.isEmpty()) {
            executeReal(request)
        } else {
            InterceptorChainImpl(this, config.interceptors, 0, request).proceed()
        }
    }

    internal suspend fun executeReal(request: KatHttpRequest): KatHttpResponse = suspendCancellableCoroutine { continuation ->
        if (closed.get()) { continuation.resumeWithException(KathttpException.Closed()); return@suspendCancellableCoroutine }
        val id = ids.getAndIncrement()
        val callback = BufferedCallback(id, continuation)
        active += id
        continuation.invokeOnCancellation { synchronized(nativeLock) { if (!closed.get()) NativeBridge.cancel(handle, id) }; active.remove(id) }
        val ok = synchronized(nativeLock) { if (closed.get()) false else NativeBridge.execute(handle, id, request.method, request.url, request.headers.map { it.name }.toTypedArray(), request.headers.map { it.value }.toTypedArray(), request.body, config.followRedirects, false, callback) }
        if (!ok) callback.fail(KathttpException.Native(-7))
    }

    fun executeStreaming(request: KatHttpRequest): KatHttpCall {
        check(!closed.get()) { "Client is closed" }
        val id = ids.getAndIncrement()
        val channel = Channel<KatHttpStreamEvent>(capacity = 8)
        val stashLock = Any()
        val stash = ArrayDeque<ByteArray>()
        var stashedBytes = 0L
        val completePending = AtomicBoolean(false)
        fun drainOneStashedChunk() {
            val next = synchronized(stashLock) {
                if (stash.isEmpty()) null else stash.removeFirst().also { stashedBytes -= it.size }
            }
            if (next != null && !channel.trySend(KatHttpStreamEvent.Body(next)).isSuccess) {
                synchronized(stashLock) { stash.addFirst(next); stashedBytes += next.size }
            }
        }
        fun finishIfDrained() {
            if (completePending.get() && synchronized(stashLock) { stash.isEmpty() }) channel.close()
        }
        val call = KatHttpCall(channel.receiveAsFlow()
            .onEach {
                if (it is KatHttpStreamEvent.Body) {
                    // Credit is returned only after this Flow element has been
                    // delivered to the collector, never when native invokes a callback.
                    NativeBridge.consume(handle, id, it.bytes.size.toLong())
                    drainOneStashedChunk()
                    finishIfDrained()
                }
            }
        ) { synchronized(nativeLock) { if (!closed.get()) NativeBridge.cancel(handle, id) } }
        val terminal = AtomicBoolean(false)
        val callback = object : NativeCallback {
            override fun onHeaders(status: Int, names: Array<String>, values: Array<String>) { if (!channel.trySend(KatHttpStreamEvent.Headers(status, names.indices.map { KatHttpHeader(names[it], values[it]) })).isSuccess) cancel() }
            override fun onBody(data: ByteArray) {
                if (channel.trySend(KatHttpStreamEvent.Body(data)).isSuccess) return
                val overflow = synchronized(stashLock) {
                    if (stashedBytes + data.size > config.maxStreamingBufferedBodyBytes) true
                    else { stash.addLast(data); stashedBytes += data.size; false }
                }
                if (overflow) cancel()
            }
            override fun onComplete() { if (terminal.compareAndSet(false,true)) { active.remove(id); completePending.set(true); finishIfDrained() } }
            override fun onError(code: Int) { if (terminal.compareAndSet(false,true)) { active.remove(id); channel.close(mapError(code)) } }
            fun cancel() { synchronized(nativeLock) { if (!closed.get()) NativeBridge.cancel(handle,id) }; onError(-6) }
        }
        active += id
        if (!synchronized(nativeLock) { if (closed.get()) false else NativeBridge.execute(handle,id,request.method,request.url,request.headers.map{it.name}.toTypedArray(),request.headers.map{it.value}.toTypedArray(),request.body,config.followRedirects,true,callback) }) callback.onError(-7)
        return call
    }

    private class InterceptorChainImpl(
        override val client: KatHttpClient,
        private val interceptors: List<HttpInterceptor>,
        private val index: Int,
        override val request: KatHttpRequest,
    ) : InterceptorChain {
        override suspend fun proceed(request: KatHttpRequest): KatHttpResponse {
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
        active.clear()
        NativeBridge.destroyClient(handle)
    }

    private inner class BufferedCallback(private val id: Long, private val continuation: CancellableContinuation<KatHttpResponse>) : NativeCallback {
        private val terminal = AtomicBoolean(false)
        private var status = 0
        private var headers = emptyList<KatHttpHeader>()
        private val body = ByteArrayOutputStream()
        override fun onHeaders(status: Int, names: Array<String>, values: Array<String>) { if (!terminal.get()) { this.status = status; headers = names.indices.map { KatHttpHeader(names[it], values[it]) } } }
        override fun onBody(data: ByteArray) {
            if (terminal.get()) return
            if (body.size().toLong() + data.size > config.maxBufferedBodyBytes) { synchronized(nativeLock) { if (!closed.get()) NativeBridge.cancel(handle, id) }; fail(KathttpException.BodyTooLarge()) } else body.write(data)
        }
        override fun onComplete() { if (terminal.compareAndSet(false, true)) { active.remove(id); if (continuation.isActive) {
            val resp = KatHttpResponse(status, headers, body.toByteArray())
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

sealed interface KatHttpStreamEvent {
    data class Headers(val status: Int, val headers: List<KatHttpHeader>) : KatHttpStreamEvent
    data class Body(val bytes: ByteArray) : KatHttpStreamEvent
}

class KatHttpCall internal constructor(val events: Flow<KatHttpStreamEvent>, private val cancelAction: () -> Unit) : AutoCloseable {
    private val cancelled = AtomicBoolean(false)
    fun cancel() { if (cancelled.compareAndSet(false,true)) cancelAction() }
    override fun close() = cancel()
}

private fun mapError(code: Int): KathttpException = when (code) {
    -1 -> KathttpException.Dns()
    -3 -> QuicTransportException("QUIC transport error")
    -4 -> TlsHandshakeException("TLS handshake error")
    -5, -6, -7 -> CertificateVerificationException("Certificate verification failed (code $code)")
    -9 -> KathttpException.Timeout(KatHttpTimeoutPhase.Call)
    -15 -> KathttpException.Timeout(KatHttpTimeoutPhase.Dns)
    -16 -> KathttpException.Timeout(KatHttpTimeoutPhase.Connect)
    -17 -> KathttpException.Timeout(KatHttpTimeoutPhase.Handshake)
    -18 -> KathttpException.Timeout(KatHttpTimeoutPhase.ResponseHeaders)
    -19 -> KathttpException.Timeout(KatHttpTimeoutPhase.Read)
    -20 -> KathttpException.Timeout(KatHttpTimeoutPhase.Write)
    -21 -> KathttpException.Timeout(KatHttpTimeoutPhase.Call)
    -13 -> KathttpException.Closed()
    else -> KathttpException.Native(code)
}

suspend fun KatHttpClient.get(url: String, headers: List<KatHttpHeader> = emptyList()) = execute(KatHttpRequest("GET", url, headers))
suspend fun KatHttpClient.post(url: String, body: ByteArray, headers: List<KatHttpHeader> = emptyList()) = execute(KatHttpRequest("POST", url, headers, body))
suspend fun KatHttpClient.put(url: String, body: ByteArray, headers: List<KatHttpHeader> = emptyList()) = execute(KatHttpRequest("PUT", url, headers, body))
suspend fun KatHttpClient.delete(url: String, headers: List<KatHttpHeader> = emptyList()) = execute(KatHttpRequest("DELETE", url, headers))
suspend fun KatHttpClient.patch(url: String, body: ByteArray, headers: List<KatHttpHeader> = emptyList()) = execute(KatHttpRequest("PATCH", url, headers, body))
suspend fun KatHttpClient.head(url: String, headers: List<KatHttpHeader> = emptyList()) = execute(KatHttpRequest("HEAD", url, headers))
