package dev.kathttp3

/** A single link in the request/response pipeline, ktor/okhttp style. */
interface InterceptorChain {
    val request: KatHttp3Request
    val client: KatHttp3Client
    suspend fun proceed(request: KatHttp3Request = this.request): KatHttp3Response
}

/** Transforms requests and/or responses around [InterceptorChain.proceed]. */
interface HttpInterceptor {
    suspend fun intercept(chain: InterceptorChain): KatHttp3Response
}
