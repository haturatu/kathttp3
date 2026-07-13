package dev.kathttp3

import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL

/**
 * A resolved IP candidate returned from a [DnsResolver].
 *
 * The address family (IPv4 vs IPv6) is derived from the IP string by the
 * native layer, so only the textual [ip] and the [port] need to be supplied.
 */
data class ResolvedAddress(val ip: String, val port: Int)

/**
 * Pluggable name resolution. Implement this to replace the built-in DNS
 * (e.g. with DNS-over-HTTPS). [resolve] runs on the native QUIC worker thread,
 * so it must be synchronous and thread-safe; do not touch Android UI or
 * coroutine contexts here.
 */
interface DnsResolver {
    fun resolve(host: String, port: Int): List<ResolvedAddress>
}

/** Uses the platform resolver (InetAddress), which on Android honors the
 * system DNS / private DNS (DoT) and Happy Eyeballs ordering. */
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

    override fun resolve(host: String, port: Int): List<ResolvedAddress> {
        val out = mutableListOf<ResolvedAddress>()
        for (type in types) {
            val url = URL("$endpoint?name=${host.encode()}&type=$type")
            val conn = url.openConnection() as HttpURLConnection
            try {
                conn.requestMethod = "GET"
                conn.setRequestProperty("Accept", "application/dns-json")
                conn.connectTimeout = connectTimeoutMs
                conn.readTimeout = readTimeoutMs
                conn.inputStream.bufferedReader().use { reader ->
                    val answers = JSONObject(reader.readText())
                        .optJSONArray("Answer") ?: JSONArray()
                    for (i in 0 until answers.length()) {
                        val data = answers.optJSONObject(i)?.optString("data") ?: continue
                        val ip = data.trim()
                        if (ip.isNotEmpty()) out += ResolvedAddress(ip, port)
                    }
                }
            } catch (_: Exception) {
                // Best-effort: keep whatever addresses we already collected.
            } finally {
                conn.disconnect()
            }
        }
        return out
    }

    private fun String.encode(): String = buildString {
        for (c in this@encode) {
            if (c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '-' || c == '_' || c == '.' || c == '~') append(c)
            else append("%%%02X".format(c.code))
        }
    }
}
