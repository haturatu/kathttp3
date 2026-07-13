package dev.kathttp

import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertEquals

class ModelsTest {
    @Test fun configValidation() { assertFailsWith<IllegalArgumentException> { KatHttpClientConfig(maxBufferedBodyBytes = 0) } }
    @Test fun phaseTimeoutValidation() {
        assertFailsWith<IllegalArgumentException> { KatHttpClientConfig(readTimeoutMillis = 0) }
        assertEquals(10_000, KatHttpClientConfig().handshakeTimeoutMillis)
        assertEquals(30_000, KatHttpClientConfig().callTimeoutMillis)
    }
    @Test fun requestRequiresHttps() { assertFailsWith<IllegalArgumentException> { KatHttpRequest("GET", "http://example.com") } }
    @Test fun headerRejectsInjection() { assertFailsWith<IllegalArgumentException> { KatHttpHeader("x", "ok\r\nbad") } }
    @Test fun immutableValueBasics() { assertEquals("GET", KatHttpRequest("GET", "https://example.com").method) }
}
