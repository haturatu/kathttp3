package dev.kathttp3

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlin.random.Random

data class KatHttp3RetryPolicy(
    val maxAttempts: Int = 2,
    val retryIdempotentMethods: Boolean = true,
    val retryOnConnectionFailure: Boolean = true,
    val initialBackoffMillis: Long = 100,
    val maxBackoffMillis: Long = 2_000,
) {
    init { require(maxAttempts >= 1 && initialBackoffMillis >= 0 && maxBackoffMillis >= initialBackoffMillis) }
    fun canRetry(request: KatHttp3Request, error: Throwable): Boolean {
        if (!retryOnConnectionFailure || error is CancellationException) return false
        if (error is CertificateVerificationException || error is TlsHandshakeException) return false
        if (!isSafeConnectionRetry(error)) return false
        return retryIdempotentMethods && request.method in setOf("GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE")
    }
}

private fun isSafeConnectionRetry(error: Throwable): Boolean = when (error) {
    is QuicTransportException, is KatHttp3Exception.Dns, is KatHttp3Exception.NetworkLost -> true
    is KatHttp3Exception.Timeout -> error.phase in setOf(KatHttp3TimeoutPhase.Dns, KatHttp3TimeoutPhase.Connect, KatHttp3TimeoutPhase.Handshake)
    else -> false
}

/** Retries failed requests with exponential backoff. Cancellation is never retried. */
class RetryInterceptor(
    private val maxRetries: Int = 3,
    private val initialDelayMillis: Long = 500,
    private val maxDelayMillis: Long = 10_000,
    private val retryable: (Throwable) -> Boolean = {
        isSafeConnectionRetry(it)
    },
) : HttpInterceptor {
    override suspend fun intercept(chain: InterceptorChain): KatHttp3Response {
        var attempt = 0
        var delayMs = initialDelayMillis
        while (true) {
            try {
                return chain.proceed(chain.request)
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                if (attempt >= maxRetries || !retryable(e)) throw e
                attempt++
                delay(delayMs)
                delayMs = (delayMs * 2).coerceAtMost(maxDelayMillis)
            }
        }
    }
}

/** Safe retry interceptor that keeps one attempt budget for the complete call. */
class PolicyRetryInterceptor(private val policy: KatHttp3RetryPolicy = KatHttp3RetryPolicy()) : HttpInterceptor {
    override suspend fun intercept(chain: InterceptorChain): KatHttp3Response {
        var attempt = 1
        var backoff = policy.initialBackoffMillis
        while (true) try {
            return chain.proceed(chain.request)
        } catch (error: Exception) {
            if (attempt >= policy.maxAttempts || !policy.canRetry(chain.request, error)) throw error
            attempt++
            if (backoff > 0) delay(backoff + Random.nextLong(0, backoff / 4 + 1))
            backoff = (backoff * 2).coerceAtMost(policy.maxBackoffMillis)
        }
    }
}
