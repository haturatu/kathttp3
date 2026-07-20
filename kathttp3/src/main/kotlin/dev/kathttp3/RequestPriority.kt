package dev.kathttp3

internal fun KatHttp3Request.headersWithHttpPriority(): List<KatHttp3Header> {
    if (headers.any { it.name.equals("priority", ignoreCase = true) }) return headers
    val value = buildString {
        append("u=")
        append(priority.urgency)
        if (priority.incremental) append(", i")
    }
    return headers + KatHttp3Header("priority", value)
}
