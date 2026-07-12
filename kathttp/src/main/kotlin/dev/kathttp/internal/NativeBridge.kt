package dev.kathttp.internal

internal interface NativeCallback {
    fun onHeaders(status: Int, names: Array<String>, values: Array<String>)
    fun onBody(data: ByteArray)
    fun onComplete()
    fun onError(code: Int)
}

internal object NativeBridge {
    init { System.loadLibrary("kathttp") }
    external fun createClient(connectMs: Long, requestMs: Long, idleMs: Long, maxRedirects: Int, trustMode: Int, insecureCert: Boolean, caCertificateFile: String?): Long
    external fun closeClient(handle: Long)
    external fun destroyClient(handle: Long)
    external fun execute(handle: Long, id: Long, method: String, url: String, names: Array<String>, values: Array<String>, body: ByteArray?, followRedirects: Boolean, callback: NativeCallback): Boolean
    external fun cancel(handle: Long, id: Long)
}
