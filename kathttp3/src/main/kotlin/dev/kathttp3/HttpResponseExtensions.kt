package dev.kathttp3

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.util.zip.GZIPInputStream
import java.util.zip.InflaterInputStream

/** Decodes `content-encoding` (gzip / deflate / br) and strips the encoding headers. */
fun KatHttp3Response.decodeContent(): KatHttp3Response {
    val encoding = headers.firstOrNull { it.name == "content-encoding" }?.value?.lowercase() ?: return this
    val decoded = when (encoding) {
        "gzip" -> gzipDecode(body)
        "deflate" -> inflateDecode(body)
        "br" -> brotliDecode(body)
        else -> return this
    }
    val newHeaders = headers.filterNot { it.name == "content-encoding" || it.name == "content-length" }
    return KatHttp3Response(status, newHeaders, decoded, protocol)
}

/** Writes the (already buffered) response body to a file. */
fun KatHttp3Response.saveTo(file: File) {
    FileOutputStream(file).use { it.write(body) }
}

private fun gzipDecode(data: ByteArray): ByteArray {
    val out = ByteArrayOutputStream()
    GZIPInputStream(ByteArrayInputStream(data)).use { it.copyTo(out) }
    return out.toByteArray()
}

private fun inflateDecode(data: ByteArray): ByteArray {
    val out = ByteArrayOutputStream()
    InflaterInputStream(ByteArrayInputStream(data)).use { it.copyTo(out) }
    return out.toByteArray()
}

private fun brotliDecode(data: ByteArray): ByteArray {
    return try {
        val clazz = Class.forName("android.util.BrotliInputStream")
        val ctor = clazz.getConstructor(ByteArrayInputStream::class.java)
        val `in` = ctor.newInstance(ByteArrayInputStream(data)) as java.io.InputStream
        val out = ByteArrayOutputStream()
        `in`.use { it.copyTo(out) }
        out.toByteArray()
    } catch (_: Throwable) {
        data
    }
}
