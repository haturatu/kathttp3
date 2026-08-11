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
            validateParameter(name, "field name")
            parts += Part(name, null, "text/plain; charset=utf-8", value.toByteArray(Charsets.UTF_8))
        }

        fun addFile(name: String, filename: String, contentType: String, data: ByteArray): Builder = apply {
            validateParameter(name, "field name")
            validateParameter(filename, "filename")
            require(
                contentType.isNotBlank() &&
                    contentType.none { invalidHeaderCharacter(it) || it.code > 0x7e },
            ) {
                "content type contains an invalid header character"
            }
            parts += Part(name, filename, contentType, data)
        }

        fun build(): MultipartBody {
            val out = ByteArrayOutputStream()
            val crlf = "\r\n".toByteArray(Charsets.US_ASCII)
            val dash = "--".toByteArray(Charsets.US_ASCII)
            for (p in parts) {
                out.write(dash); out.write(boundary.toByteArray(Charsets.US_ASCII)); out.write(crlf)
                val cd = buildString {
                    append("Content-Disposition: form-data; name=\"")
                    append(quotedParameter(p.name, percentEncodeNonAscii = false))
                    append('"')
                    if (p.filename != null) {
                        append("; filename=\"")
                        append(quotedParameter(p.filename, percentEncodeNonAscii = true))
                        append('"')
                    }
                }
                out.write(cd.toByteArray(Charsets.UTF_8)); out.write(crlf)
                out.write("""Content-Type: ${p.contentType}""".toByteArray(Charsets.US_ASCII)); out.write(crlf)
                out.write(crlf); out.write(p.data); out.write(crlf)
            }
            out.write(dash); out.write(boundary.toByteArray(Charsets.US_ASCII)); out.write(dash); out.write(crlf)
            return MultipartBody(out.toByteArray(), "multipart/form-data; boundary=$boundary")
        }

        private fun validateParameter(value: String, label: String) {
            require(value.isNotEmpty() && value.none(::invalidHeaderCharacter)) {
                "$label contains an invalid header character"
            }
        }

        private fun quotedParameter(value: String, percentEncodeNonAscii: Boolean): String =
            buildString {
                if (!percentEncodeNonAscii) {
                    for (character in value) {
                        if (character == '"' || character == '\\') append('\\')
                        append(character)
                    }
                    return@buildString
                }
                for (byte in value.toByteArray(Charsets.UTF_8)) {
                    val octet = byte.toInt() and 0xff
                    when {
                        octet == '"'.code || octet == '\\'.code -> {
                            append('\\')
                            append(octet.toChar())
                        }
                        octet > 0x7f -> {
                            append('%')
                            append(HEX_DIGITS[octet ushr 4])
                            append(HEX_DIGITS[octet and 0x0f])
                        }
                        else -> append(octet.toChar())
                    }
                }
            }
    }
}

private fun invalidHeaderCharacter(character: Char): Boolean =
    character == '\r' || character == '\n' || character == '\u0000' ||
        character.code < 0x20 || character.code == 0x7f

private const val HEX_DIGITS = "0123456789ABCDEF"

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
