package dev.kathttp3

/** Injects `Authorization: Bearer <token>` unless already present. */
class BearerAuthInterceptor(private val token: String) : HttpInterceptor {
    override suspend fun intercept(chain: InterceptorChain): KatHttp3Response {
        val auth = KatHttp3Header("authorization", "Bearer $token")
        val headers = chain.request.headers.filterNot { it.name == "authorization" } + auth
        return chain.proceed(chain.request.copy(headers = headers))
    }
}
