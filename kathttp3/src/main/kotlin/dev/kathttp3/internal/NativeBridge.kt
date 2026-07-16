package dev.kathttp3.internal

import dev.kathttp3.DnsResolver

internal interface NativeCallback {
    fun onHeaders(status: Int, names: Array<String>, values: Array<String>)
    fun onBody(data: ByteArray)
    fun onComplete()
    fun onError(code: Int)
}

internal object NativeBridge {
    init { System.loadLibrary("kathttp3") }
    external fun createClient(connectMs: Long, requestMs: Long, idleMs: Long, dnsMs: Long,
        handshakeMs: Long, responseHeadersMs: Long, readMs: Long, writeMs: Long, callMs: Long, consumerStallMs: Long,
        maxRedirects: Int, trustMode: Int, insecureCert: Boolean, enableCookies: Boolean, enable0Rtt: Boolean, qlogEnabled: Boolean, qlogLogcatEnabled: Boolean, caCertificateFile: String?,
        qlogPathPrefix: String?, resolver: DnsResolver?): Long
    external fun closeClient(handle: Long)
    external fun destroyClient(handle: Long)
    external fun execute(handle: Long, id: Long, method: String, url: String, names: Array<String>, values: Array<String>, body: ByteArray?, followRedirects: Boolean, streaming: Boolean, streamingRequestBody: Boolean, streamingContentLength: Long, callback: NativeCallback): Boolean
    external fun consume(handle: Long, id: Long, bytes: Long): Boolean
    external fun appendRequestBody(handle: Long, id: Long, data: ByteArray?, finished: Boolean): Int
    external fun cancel(handle: Long, id: Long)
    external fun networkChanged(handle: Long, generation: Long, networkHandle: Long)
}
