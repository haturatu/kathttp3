package dev.kathttp3

/** Adds default headers that are absent from the request. */
class CommonHeadersInterceptor(private val headers: List<KatHttp3Header>) : HttpInterceptor {
    constructor(vararg headers: KatHttp3Header) : this(headers.toList())

    override suspend fun intercept(chain: InterceptorChain): KatHttp3Response {
        val merged = chain.request.headers.toMutableList()
        for (h in headers) {
            if (merged.none { it.name == h.name }) merged += h
        }
        return chain.proceed(chain.request.copy(headers = merged))
    }
}
