package dev.kathttp.internal

import dev.kathttp.DnsResolver

internal interface NativeCallback {
    fun onHeaders(status: Int, names: Array<String>, values: Array<String>)
    fun onBody(data: ByteArray)
    fun onComplete()
    fun onError(code: Int)
}

internal object NativeBridge {
    init { System.loadLibrary("kathttp") }
    external fun createClient(connectMs: Long, requestMs: Long, idleMs: Long, dnsMs: Long,
        handshakeMs: Long, responseHeadersMs: Long, readMs: Long, writeMs: Long, callMs: Long,
        maxRedirects: Int, trustMode: Int, insecureCert: Boolean, caCertificateFile: String?,
        resolver: DnsResolver?): Long
    external fun closeClient(handle: Long)
    external fun destroyClient(handle: Long)
    external fun execute(handle: Long, id: Long, method: String, url: String, names: Array<String>, values: Array<String>, body: ByteArray?, followRedirects: Boolean, streaming: Boolean, callback: NativeCallback): Boolean
    external fun consume(handle: Long, id: Long, bytes: Long): Boolean
    external fun cancel(handle: Long, id: Long)
}
