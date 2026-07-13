package dev.kathttp3

import java.io.ByteArrayOutputStream
import java.nio.charset.Charset
import java.util.UUID

/** Builds a `multipart/form-data` request body. */
class MultipartBody private constructor(val bytes: ByteArray, val contentType: String) {
    data class Part(val name: String, val filename: String?, val contentType: String, val data: ByteArray)

    class Builder {
        private val parts = mutableListOf<Part>()
        private val boundary = "kathttp3-${UUID.randomUUID()}"

        fun addFormField(name: String, value: String): Builder = apply {
            parts += Part(name, null, "text/plain; charset=utf-8", value.toByteArray(Charsets.UTF_8))
        }

        fun addFile(name: String, filename: String, contentType: String, data: ByteArray): Builder = apply {
            parts += Part(name, filename, contentType, data)
        }

        fun build(): MultipartBody {
            val out = ByteArrayOutputStream()
            val crlf = "\r\n".toByteArray(Charsets.US_ASCII)
            val dash = "--".toByteArray(Charsets.US_ASCII)
            for (p in parts) {
                out.write(dash); out.write(boundary.toByteArray(Charsets.US_ASCII)); out.write(crlf)
                val cd = buildString {
                    append("""Content-Disposition: form-data; name="${p.name}"""")
                    if (p.filename != null) append("""; filename="${p.filename}"""")
                }
                out.write(cd.toByteArray(Charsets.US_ASCII)); out.write(crlf)
                out.write("""Content-Type: ${p.contentType}""".toByteArray(Charsets.US_ASCII)); out.write(crlf)
                out.write(crlf); out.write(p.data); out.write(crlf)
            }
            out.write(dash); out.write(boundary.toByteArray(Charsets.US_ASCII)); out.write(dash); out.write(crlf)
            return MultipartBody(out.toByteArray(), "multipart/form-data; boundary=$boundary")
        }
    }
}

fun multipartRequest(
    url: String,
    method: String = "POST",
    block: MultipartBody.Builder.() -> Unit,
): KatHttp3Request {
    val mp = MultipartBody.Builder().apply(block).build()
    return KatHttp3Request(method, url, listOf(KatHttp3Header("content-type", mp.contentType)), mp.bytes)
}

/** Builds `application/x-www-form-urlencoded` request bodies. */
object FormBody {
    fun build(fields: Map<String, String>, charset: Charset = Charsets.UTF_8): ByteArray =
        fields.entries.joinToString("&") { (k, v) -> "${encode(k, charset)}=${encode(v, charset)}" }
            .toByteArray(charset)

    fun request(url: String, method: String = "POST", fields: Map<String, String>): KatHttp3Request =
        KatHttp3Request(method, url, listOf(KatHttp3Header("content-type", "application/x-www-form-urlencoded")), build(fields))

    private fun encode(s: String, charset: Charset): String {
        val sb = StringBuilder()
        for (c in s.toByteArray(charset)) {
            val v = c.toInt() and 0xFF
            if (v in 'a'.code..'z'.code || v in 'A'.code..'Z'.code || v in '0'.code..'9'.code ||
                v == '-'.code || v == '_'.code || v == '.'.code || v == '~'.code
            ) {
                sb.append(v.toChar())
            } else {
                sb.append(String.format("%%%02X", v))
            }
        }
        return sb.toString()
    }
}
