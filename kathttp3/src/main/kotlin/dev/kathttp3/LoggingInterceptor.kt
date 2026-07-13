package dev.kathttp3

import android.util.Log

/** Logs each request and its outcome (status / failure / duration). */
class LoggingInterceptor(
    private val tag: String = "KatHttp3",
    private val logBody: Boolean = false,
) : HttpInterceptor {
    override suspend fun intercept(chain: InterceptorChain): KatHttp3Response {
        val req = chain.request
        val start = System.nanoTime()
        Log.d(tag, "-> ${req.method} ${req.url} (${req.body?.size ?: 0} bytes)")
        return try {
            val res = chain.proceed(req)
            val ms = (System.nanoTime() - start) / 1_000_000
            Log.d(tag, "<- ${res.status} ${req.url} (${res.body.size} bytes, ${ms}ms)")
            res
        } catch (e: Throwable) {
            val ms = (System.nanoTime() - start) / 1_000_000
            Log.d(tag, "<- FAIL ${req.url} ${e::class.simpleName} (${ms}ms)")
            throw e
        }
    }
}
