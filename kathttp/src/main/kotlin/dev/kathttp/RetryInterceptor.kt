package dev.kathttp

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay

/** Retries failed requests with exponential backoff. Cancellation is never retried. */
class RetryInterceptor(
    private val maxRetries: Int = 3,
    private val initialDelayMillis: Long = 500,
    private val maxDelayMillis: Long = 10_000,
    private val retryable: (Throwable) -> Boolean = {
        it is QuicTransportException || it is KathttpException.Dns || it is KathttpException.Timeout
    },
) : HttpInterceptor {
    override suspend fun intercept(chain: InterceptorChain): KatHttpResponse {
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
