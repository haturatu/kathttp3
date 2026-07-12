package dev.kathttp

/** A single link in the request/response pipeline, ktor/okhttp style. */
interface InterceptorChain {
    val request: KatHttpRequest
    val client: KatHttpClient
    suspend fun proceed(request: KatHttpRequest = this.request): KatHttpResponse
}

/** Transforms requests and/or responses around [InterceptorChain.proceed]. */
interface HttpInterceptor {
    suspend fun intercept(chain: InterceptorChain): KatHttpResponse
}
