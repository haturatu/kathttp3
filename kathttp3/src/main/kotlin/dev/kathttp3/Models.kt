package dev.kathttp3

import java.io.IOException
import java.io.File
import kotlinx.coroutines.flow.Flow

/** Certificate trust policy, mapped to the native `kathttp3_trust_mode`. */
enum class TrustMode {
    PLATFORM,          /* Android: X509TrustManager; else: system store */
    EMBEDDED_MOZILLA,  /* bundled Mozilla CA bundle */
    CUSTOM_CA;         /* PEM bundle at caCertificateFile */
    val native: Int get() = ordinal
}

data class KatHttp3ClientConfig(
    val connectTimeoutMillis: Long = 10_000,
    val requestTimeoutMillis: Long = 30_000,
    val idleTimeoutMillis: Long = 30_000,
    val dnsTimeoutMillis: Long = connectTimeoutMillis,
    val handshakeTimeoutMillis: Long = connectTimeoutMillis,
    val responseHeadersTimeoutMillis: Long = requestTimeoutMillis,
    val readTimeoutMillis: Long = idleTimeoutMillis,
    val writeTimeoutMillis: Long = idleTimeoutMillis,
    val callTimeoutMillis: Long = requestTimeoutMillis,
    /** Maximum time a streaming consumer may keep its QUIC receive window full. */
    val consumerStallTimeoutMillis: Long = readTimeoutMillis,
    val followRedirects: Boolean = true,
    val maxRedirects: Int = 10,
    val maxBufferedBodyBytes: Long = 16L * 1024 * 1024,
    val maxStreamingBufferedBodyBytes: Long = 4L * 1024 * 1024,
    /** Maximum Kotlin-owned queued response bytes for one streaming call. */
    val maxStreamingBufferedBytesPerStream: Long = 1L * 1024 * 1024,
    /** Maximum Kotlin-owned queued response bytes across this client. */
    val maxStreamingBufferedBytesPerConnection: Long = 16L * 1024 * 1024,
    /** Local admission-control limit; distinct from QUIC peer MAX_STREAMS. */
    val maxActiveStreamsPerOrigin: Int = 8,
    /** Maximum calls waiting for a local admission-control permit per origin. */
    val maxQueuedRequestsPerOrigin: Int = 64,
    /** Time a call may wait before native request creation; excludes read timeout. */
    val queueTimeoutMillis: Long = 30_000,
    val caCertificateFile: String? = null,
    /**
     * Optional app-private path prefix for ngtcp2 qlog diagnostics. Each QUIC
     * connection creates a separate `${qlogPathPrefix}-<pid>-<id>.qlog` file.
     * qlog can reveal connection metadata, so keep this disabled in releases.
     */
    val qlogPathPrefix: String? = null,
    /** Enables private ngtcp2 qlog diagnostics. Disabled by default. */
    val qlogEnabled: Boolean = false,
    val trustMode: TrustMode = TrustMode.PLATFORM,
    val insecureCert: Boolean = false,
    /** Experimental: enables KatHttp3's in-memory cookie jar. It deliberately
     * has no PSL integration, so it is off by default. */
    val enableCookies: Boolean = false,
    /** 0-RTT for replay-safe GET/HEAD requests without credentials. Enabled by
     * default; only credential-free, bodyless GET/HEAD requests use early data. */
    val enable0Rtt: Boolean = true,
    val expectSuccess: Boolean = false,
    val interceptors: List<HttpInterceptor> = emptyList(),
    val resolver: DnsResolver? = null,
) {
    init {
        require(connectTimeoutMillis > 0 && requestTimeoutMillis > 0 && idleTimeoutMillis > 0)
        require(dnsTimeoutMillis > 0 && handshakeTimeoutMillis > 0)
        require(responseHeadersTimeoutMillis > 0 && readTimeoutMillis > 0)
        require(writeTimeoutMillis > 0 && callTimeoutMillis > 0)
        require(consumerStallTimeoutMillis > 0)
        require(maxRedirects >= 0 && maxBufferedBodyBytes > 0 && maxStreamingBufferedBodyBytes > 0)
        require(maxStreamingBufferedBytesPerStream > 0 && maxStreamingBufferedBytesPerConnection > 0)
        require(maxStreamingBufferedBytesPerStream <= maxStreamingBufferedBytesPerConnection)
        require(maxActiveStreamsPerOrigin > 0 && maxQueuedRequestsPerOrigin >= 0)
        require(queueTimeoutMillis > 0)
        require(caCertificateFile == null || caCertificateFile.isNotBlank())
        require(qlogPathPrefix == null || qlogPathPrefix.isNotBlank())
        require(!qlogEnabled || !qlogPathPrefix.isNullOrBlank()) {
            "qlogPathPrefix is required when qlogEnabled is true"
        }
    }
}

enum class KatHttp3TimeoutPhase { Dns, Connect, Handshake, ResponseHeaders, Read, Write, Call }

data class KatHttp3Header(val name: String, val value: String) {
    init { require(name.isNotBlank() && name == name.lowercase() && name.none { it <= ' ' || it == ':' }); require(value.none { it == '\r' || it == '\n' }) }
}

sealed interface KatHttp3RequestBody {
    data class Bytes(val value: ByteArray) : KatHttp3RequestBody
    data class FileBody(val file: File) : KatHttp3RequestBody
    data class Stream(val contentLength: Long? = null, val source: Flow<ByteArray>) : KatHttp3RequestBody
}

data class KatHttp3Request(val method: String, val url: String, val headers: List<KatHttp3Header> = emptyList(), val body: ByteArray? = null, val streamingBody: KatHttp3RequestBody? = null) {
    init { require(method.matches(Regex("[A-Z!#$%&'*+.^_`|~-]+"))); require(url.startsWith("https://")) }
}

data class KatHttp3Response(val status: Int, val headers: List<KatHttp3Header>, val body: ByteArray, val protocol: String = "h3")

sealed class KatHttp3Exception(message: String) : IOException(message) {
    class Dns : KatHttp3Exception("DNS resolution failed")
    class Timeout(val phase: KatHttp3TimeoutPhase) : KatHttp3Exception("${phase.name} timed out")
    class Closed : KatHttp3Exception("Client is closed")
    class BodyTooLarge : KatHttp3Exception("Response exceeds configured body limit")
    class ConsumerStallTimeout : KatHttp3Exception("Streaming response consumer stalled")
    class RequestQueueFull(val origin: String) : KatHttp3Exception("Request queue is full for $origin")
    class RequestQueueTimeout(val origin: String, val timeoutMillis: Long) :
        KatHttp3Exception("Request queue timed out for $origin after $timeoutMillis ms")
    class Native(val code: Int) : KatHttp3Exception("Native HTTP/3 error: $code")
}

class ResponseException(val statusCode: Int, message: String, val response: KatHttp3Response?) : KatHttp3Exception(message)

class CertificateVerificationException(message: String) : KatHttp3Exception(message)
class TlsHandshakeException(message: String) : KatHttp3Exception(message)
class QuicTransportException(message: String) : KatHttp3Exception(message)
