package dev.kathttp3

import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.util.LinkedHashMap
import java.util.Locale
import kotlin.math.min

/**
 * A resolved IP candidate returned from a [DnsResolver].
 *
 * The address family (IPv4 vs IPv6) is derived from the IP string by the
 * native layer, so only the textual [ip] and the [port] need to be supplied.
 */
data class ResolvedAddress(val ip: String, val port: Int)

/**
 * Pluggable name resolution. Implement this to replace the built-in DNS
 * (e.g. with DNS-over-HTTPS). [resolve] runs on KatHttp3's bounded DNS worker
 * pool, so it must be synchronous and thread-safe; do not touch Android UI or
 * coroutine contexts here.
 */
interface DnsResolver {
    fun resolve(host: String, port: Int): List<ResolvedAddress>
}

/** Uses the platform resolver (InetAddress), which on Android honors the
 * system DNS / private DNS (DoT). The native client plans address-family
 * fallback after this resolver returns its addresses. */
class PlatformDnsResolver : DnsResolver {
    override fun resolve(host: String, port: Int): List<ResolvedAddress> =
        InetAddress.getAllByName(host).map { ResolvedAddress(it.hostAddress ?: return@map null, port) }
            .filterNotNull()
}

/**
 * Minimal DNS-over-HTTPS resolver (RFC 8484, JSON API). Uses the system
 * HTTPS stack, so it is independent of KatHttp3's own connections.
 *
 * Example endpoints:
 *  - https://cloudflare-dns.com/dns-query   (Accept: application/dns-json)
 *  - https://dns.google/resolve             (Accept: application/dns-json)
 */
class DohResolver(
    private val endpoint: String = "https://cloudflare-dns.com/dns-query",
    private val types: List<String> = listOf("A", "AAAA"),
    private val connectTimeoutMs: Int = 5000,
    private val readTimeoutMs: Int = 5000,
) : DnsResolver {

    private data class CacheEntry(
        val addresses: List<ResolvedAddress>,
        val expiresAtNanos: Long,
    )

    private data class QueryResult(
        val addresses: List<ResolvedAddress>,
        val positiveTtlMillis: Long?,
        val negativeTtlMillis: Long?,
        val cacheableNegative: Boolean,
    )

    private val cache = object : LinkedHashMap<String, CacheEntry>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, CacheEntry>?): Boolean =
            size > MAX_CACHE_ENTRIES
    }

    override fun resolve(host: String, port: Int): List<ResolvedAddress> {
        val key = "${host.lowercase(Locale.ROOT).trimEnd('.')}\u0000$port"
        val now = System.nanoTime()
        synchronized(cache) {
            cache[key]?.let { entry ->
                if (entry.expiresAtNanos > now) return entry.addresses
                cache.remove(key)
            }
        }

        val out = mutableListOf<ResolvedAddress>()
        var positiveTtlMillis: Long? = null
        var negativeTtlMillis: Long? = null
        var allQueriesHaveCacheableNegative = true
        for (type in types) {
            val result = query(host, port, type)
            if (result == null) {
                allQueriesHaveCacheableNegative = false
                continue
            }
            out += result.addresses
            result.positiveTtlMillis?.let {
                positiveTtlMillis = positiveTtlMillis?.let { current -> min(current, it) } ?: it
            }
            if (!result.cacheableNegative) allQueriesHaveCacheableNegative = false
            result.negativeTtlMillis?.let {
                negativeTtlMillis = negativeTtlMillis?.let { current -> min(current, it) } ?: it
            }
        }

        val ttlMillis = when {
            out.isNotEmpty() -> positiveTtlMillis
            allQueriesHaveCacheableNegative -> negativeTtlMillis
            else -> null
        }
        if (ttlMillis != null && ttlMillis > 0) {
            val boundedTtl = min(ttlMillis, MAX_CACHE_TTL_MILLIS)
            val expiresAt = now + boundedTtl * NANOS_PER_MILLI
            synchronized(cache) { cache[key] = CacheEntry(out.toList(), expiresAt) }
        }
        return out
    }

    private fun query(host: String, port: Int, type: String): QueryResult? {
        val separator = when {
            endpoint.endsWith('?') || endpoint.endsWith('&') -> ""
            '?' in endpoint -> "&"
            else -> "?"
        }
        val url = URL(
            "$endpoint${separator}name=${encodeUriQueryComponent(host)}" +
                "&type=${encodeUriQueryComponent(type)}",
        )
        val conn = url.openConnection() as HttpURLConnection
        return try {
            conn.requestMethod = "GET"
            conn.setRequestProperty("Accept", "application/dns-json")
            conn.connectTimeout = connectTimeoutMs
            conn.readTimeout = readTimeoutMs
            conn.inputStream.bufferedReader().use { reader ->
                parseResponse(JSONObject(reader.readText()), port)
            }
        } catch (_: Exception) {
            // Transport and malformed-response failures are not DNS negatives.
            null
        } finally {
            conn.disconnect()
        }
    }

    private fun parseResponse(response: JSONObject, port: Int): QueryResult {
        val status = response.optInt("Status", -1)
        val answers = response.optJSONArray("Answer") ?: JSONArray()
        val addresses = mutableListOf<ResolvedAddress>()
        var answerTtlMillis: Long? = null
        for (i in 0 until answers.length()) {
            val answer = answers.optJSONObject(i) ?: continue
            val ttlMillis = ttlMillis(answer.optLong("TTL", -1))
            ttlMillis?.let {
                answerTtlMillis = answerTtlMillis?.let { current -> min(current, it) } ?: it
            }
            if (answer.optInt("type") !in setOf(TYPE_A, TYPE_AAAA)) continue
            val ip = answer.optString("data").trim()
            if (ip.isNotEmpty()) addresses += ResolvedAddress(ip, port)
        }
        if (addresses.isNotEmpty()) {
            return QueryResult(addresses, answerTtlMillis, null, false)
        }

        val negativeTtlMillis = negativeTtlMillis(response.optJSONArray("Authority"))
        val isDnsNegative = status == DNS_STATUS_NOERROR || status == DNS_STATUS_NXDOMAIN
        return QueryResult(emptyList(), null, negativeTtlMillis, isDnsNegative && negativeTtlMillis != null)
    }

    private fun negativeTtlMillis(authority: JSONArray?): Long? {
        if (authority == null) return null
        var minimum: Long? = null
        for (i in 0 until authority.length()) {
            val soa = authority.optJSONObject(i) ?: continue
            if (soa.optInt("type") != TYPE_SOA) continue
            val soaTtlSeconds = soa.optLong("TTL", -1)
            val soaMinimumSeconds = soa.optString("data").trim().split(Regex("\\s+"))
                .lastOrNull()?.toLongOrNull() ?: continue
            val seconds = min(soaTtlSeconds, soaMinimumSeconds)
            ttlMillis(seconds)?.let { ttl -> minimum = minimum?.let { min(it, ttl) } ?: ttl }
        }
        return minimum
    }

    private fun ttlMillis(seconds: Long): Long? {
        if (seconds <= 0) return null
        return if (seconds > Long.MAX_VALUE / 1000) Long.MAX_VALUE else seconds * 1000
    }

    private companion object {
        const val TYPE_A = 1
        const val TYPE_SOA = 6
        const val TYPE_AAAA = 28
        const val DNS_STATUS_NOERROR = 0
        const val DNS_STATUS_NXDOMAIN = 3
        const val MAX_CACHE_ENTRIES = 128
        const val MAX_CACHE_TTL_MILLIS = 24L * 60 * 60 * 1000
        const val NANOS_PER_MILLI = 1_000_000L
    }
}

internal fun encodeUriQueryComponent(value: String): String = buildString {
    for (byte in value.toByteArray(Charsets.UTF_8)) {
        val octet = byte.toInt() and 0xff
        if (octet in 'a'.code..'z'.code || octet in 'A'.code..'Z'.code ||
            octet in '0'.code..'9'.code || octet == '-'.code || octet == '_'.code ||
            octet == '.'.code || octet == '~'.code
        ) {
            append(octet.toChar())
        } else {
            append('%')
            append(HEX_DIGITS[octet ushr 4])
            append(HEX_DIGITS[octet and 0x0f])
        }
    }
}

private const val HEX_DIGITS = "0123456789ABCDEF"
