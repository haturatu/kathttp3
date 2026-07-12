package dev.kathttp

/** Adds default headers that are absent from the request. */
class CommonHeadersInterceptor(private val headers: List<KatHttpHeader>) : HttpInterceptor {
    constructor(vararg headers: KatHttpHeader) : this(headers.toList())

    override suspend fun intercept(chain: InterceptorChain): KatHttpResponse {
        val merged = chain.request.headers.toMutableList()
        for (h in headers) {
            if (merged.none { it.name == h.name }) merged += h
        }
        return chain.proceed(chain.request.copy(headers = merged))
    }
}
