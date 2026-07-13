package dev.kathttp3.example

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.kathttp3.KatHttp3Client
import dev.kathttp3.KatHttp3Header
import dev.kathttp3.KatHttp3Request
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.time.TimeSource

private const val BODY_PREVIEW_CHAR_LIMIT = 16_000
private const val HTTP3_TEST_ORIGIN = "https://nghttp2.org/httpbin"
val HTTP_METHODS = listOf("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD")
private val BODY_METHODS = setOf("POST", "PUT", "PATCH", "DELETE")

/** A complete request which can be sent immediately to the public HTTP/3 test service. */
data class RequestPreset(val url: String, val headers: String, val body: String)

fun requestPreset(method: String): RequestPreset = when (method) {
    "GET" -> RequestPreset("$HTTP3_TEST_ORIGIN/get", "", "")
    "POST" -> RequestPreset(
        "$HTTP3_TEST_ORIGIN/post",
        "",
        "",
    )
    "PUT" -> RequestPreset(
        "$HTTP3_TEST_ORIGIN/put",
        "",
        "",
    )
    "DELETE" -> RequestPreset("$HTTP3_TEST_ORIGIN/delete", "", "")
    "PATCH" -> RequestPreset(
        "$HTTP3_TEST_ORIGIN/patch",
        "",
        "",
    )
    "HEAD" -> RequestPreset("$HTTP3_TEST_ORIGIN/get", "", "")
    else -> error("Unsupported example method: $method")
}

data class UiState(
    val url: String = requestPreset("GET").url,
    val method: String = "GET",
    val requestHeaders: String = requestPreset("GET").headers,
    val requestBody: String = requestPreset("GET").body,
    val loading: Boolean = false,
    val status: Int? = null,
    val responseHeaders: String = "",
    val responseBody: String = "",
    val responseBodyTruncated: Boolean = false,
    val error: String? = null,
    val durationMs: Long? = null,
    val size: Int = 0,
    val protocol: String = "",
)

class MainViewModel : ViewModel() {
    private val client = KatHttp3Client()
    private val mutable = MutableStateFlow(UiState())
    val state = mutable.asStateFlow()

    private var job: Job? = null
    private var requestGeneration = 0L

    fun setUrl(value: String) = update { copy(url = value) }
    /** Applies a ready-to-send URL, header and body set for [value]. */
    fun setMethod(value: String) = update {
        val preset = requestPreset(value)
        copy(
            method = value,
            url = preset.url,
            requestHeaders = preset.headers,
            requestBody = preset.body,
        )
    }
    fun setRequestHeaders(value: String) = update { copy(requestHeaders = value) }
    fun setRequestBody(value: String) = update { copy(requestBody = value) }

    fun clearResponse() = update {
        copy(
            status = null,
            responseHeaders = "",
            responseBody = "",
            responseBodyTruncated = false,
            error = null,
            durationMs = null,
            size = 0,
            protocol = "",
        )
    }

    fun execute() {
        val snapshot = mutable.value
        if (snapshot.loading) return

        val generation = ++requestGeneration
        mutable.value = snapshot.copy(
            loading = true,
            status = null,
            responseHeaders = "",
            responseBody = "",
            responseBodyTruncated = false,
            error = null,
            durationMs = null,
            size = 0,
            protocol = "",
        )
        job = viewModelScope.launch {
            val mark = TimeSource.Monotonic.markNow()
            try {
                val headers = parseHeaders(snapshot.requestHeaders)
                val body = snapshot.requestBody
                    .takeIf { methodAllowsBody(snapshot.method) && it.isNotEmpty() }
                    ?.encodeToByteArray()
                val response = client.execute(
                    KatHttp3Request(snapshot.method, snapshot.url.trim(), headers, body),
                )
                val preview = withContext(Dispatchers.Default) {
                    response.body.toPreview(BODY_PREVIEW_CHAR_LIMIT)
                }
                if (generation == requestGeneration) {
                    mutable.value = snapshot.copy(
                        loading = false,
                        status = response.status,
                        responseHeaders = response.headers.joinToString("\n") {
                            "${it.name}: ${it.value}"
                        },
                        responseBody = preview.text,
                        responseBodyTruncated = preview.truncated,
                        durationMs = mark.elapsedNow().inWholeMilliseconds,
                        size = response.body.size,
                        protocol = response.protocol,
                    )
                }
            } catch (_: CancellationException) {
                // cancel() owns the visible state.  Do not overwrite a newer request.
            } catch (error: Throwable) {
                if (generation == requestGeneration) {
                    mutable.value = snapshot.copy(
                        loading = false,
                        error = error.message ?: error.javaClass.simpleName,
                        durationMs = mark.elapsedNow().inWholeMilliseconds,
                    )
                }
            }
        }
    }

    fun cancel() {
        if (!mutable.value.loading) return
        requestGeneration++
        job?.cancel()
        job = null
        update { copy(loading = false, error = "Request cancelled") }
    }

    override fun onCleared() {
        cancel()
        client.close()
    }

    private fun update(transform: UiState.() -> UiState) {
        mutable.value = mutable.value.transform()
    }
}

internal fun methodAllowsBody(method: String): Boolean = method in BODY_METHODS

/** Parses one lowercase `name: value` header per non-empty line. */
internal fun parseHeaders(source: String): List<KatHttp3Header> =
    source.lineSequence().mapIndexedNotNull { index, line ->
        val trimmed = line.trim()
        if (trimmed.isEmpty()) return@mapIndexedNotNull null
        val separator = trimmed.indexOf(':')
        require(separator > 0) { "Header line ${index + 1} must be name: value" }
        KatHttp3Header(trimmed.substring(0, separator).trim(), trimmed.substring(separator + 1).trim())
    }.toList()

private data class BodyPreview(val text: String, val truncated: Boolean)

private fun ByteArray.toPreview(limit: Int): BodyPreview {
    // UTF-8 needs at most four bytes per code point.  Decode only enough input
    // to render the preview instead of turning a multi-megabyte body into one
    // Compose Text node.
    val previewBytes = minOf(size, limit * 4)
    val text = if (previewBytes == size) decodeToString() else copyOf(previewBytes).decodeToString()
    return BodyPreview(text.take(limit), previewBytes < size || text.length > limit)
}
