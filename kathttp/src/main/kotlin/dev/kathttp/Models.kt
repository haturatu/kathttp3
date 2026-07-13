package dev.kathttp

import java.io.IOException

/** Certificate trust policy, mapped to the native `kathttp_trust_mode`. */
enum class TrustMode {
    PLATFORM,          /* Android: X509TrustManager; else: system store */
    EMBEDDED_MOZILLA,  /* bundled Mozilla CA bundle */
    CUSTOM_CA;         /* PEM bundle at caCertificateFile */
    val native: Int get() = ordinal
}

data class KatHttpClientConfig(
    val connectTimeoutMillis: Long = 10_000,
    val requestTimeoutMillis: Long = 30_000,
    val idleTimeoutMillis: Long = 30_000,
    val dnsTimeoutMillis: Long = connectTimeoutMillis,
    val handshakeTimeoutMillis: Long = connectTimeoutMillis,
    val responseHeadersTimeoutMillis: Long = requestTimeoutMillis,
    val readTimeoutMillis: Long = idleTimeoutMillis,
    val writeTimeoutMillis: Long = idleTimeoutMillis,
    val callTimeoutMillis: Long = requestTimeoutMillis,
    val followRedirects: Boolean = true,
    val maxRedirects: Int = 10,
    val maxBufferedBodyBytes: Long = 16L * 1024 * 1024,
    val caCertificateFile: String? = null,
    val trustMode: TrustMode = TrustMode.PLATFORM,
    val insecureCert: Boolean = false,
    val expectSuccess: Boolean = false,
    val interceptors: List<HttpInterceptor> = emptyList(),
    val resolver: DnsResolver? = null,
) {
    init {
        require(connectTimeoutMillis > 0 && requestTimeoutMillis > 0 && idleTimeoutMillis > 0)
        require(dnsTimeoutMillis > 0 && handshakeTimeoutMillis > 0)
        require(responseHeadersTimeoutMillis > 0 && readTimeoutMillis > 0)
        require(writeTimeoutMillis > 0 && callTimeoutMillis > 0)
        require(maxRedirects >= 0 && maxBufferedBodyBytes > 0)
        require(caCertificateFile == null || caCertificateFile.isNotBlank())
    }
}

enum class KatHttpTimeoutPhase { Dns, Connect, Handshake, ResponseHeaders, Read, Write, Call }

data class KatHttpHeader(val name: String, val value: String) {
    init { require(name.isNotBlank() && name == name.lowercase() && name.none { it <= ' ' || it == ':' }); require(value.none { it == '\r' || it == '\n' }) }
}

data class KatHttpRequest(val method: String, val url: String, val headers: List<KatHttpHeader> = emptyList(), val body: ByteArray? = null) {
    init { require(method.matches(Regex("[A-Z!#$%&'*+.^_`|~-]+"))); require(url.startsWith("https://")) }
}

data class KatHttpResponse(val status: Int, val headers: List<KatHttpHeader>, val body: ByteArray, val protocol: String = "h3")

sealed class KathttpException(message: String) : IOException(message) {
    class Dns : KathttpException("DNS resolution failed")
    class Timeout(val phase: KatHttpTimeoutPhase) : KathttpException("${phase.name} timed out")
    class Closed : KathttpException("Client is closed")
    class BodyTooLarge : KathttpException("Response exceeds configured body limit")
    class Native(val code: Int) : KathttpException("Native HTTP/3 error: $code")
}

class ResponseException(val statusCode: Int, message: String, val response: KatHttpResponse?) : KathttpException(message)

class CertificateVerificationException(message: String) : KathttpException(message)
class TlsHandshakeException(message: String) : KathttpException(message)
class QuicTransportException(message: String) : KathttpException(message)
