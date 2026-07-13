package dev.kathttp3

import org.junit.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertEquals

class ModelsTest {
    @Test fun configValidation() { assertFailsWith<IllegalArgumentException> { KatHttp3ClientConfig(maxBufferedBodyBytes = 0) } }
    @Test fun phaseTimeoutValidation() {
        assertFailsWith<IllegalArgumentException> { KatHttp3ClientConfig(readTimeoutMillis = 0) }
        assertEquals(10_000, KatHttp3ClientConfig().handshakeTimeoutMillis)
        assertEquals(30_000, KatHttp3ClientConfig().callTimeoutMillis)
    }
    @Test fun requestRequiresHttps() { assertFailsWith<IllegalArgumentException> { KatHttp3Request("GET", "http://example.com") } }
    @Test fun headerRejectsInjection() { assertFailsWith<IllegalArgumentException> { KatHttp3Header("x", "ok\r\nbad") } }
    @Test fun immutableValueBasics() { assertEquals("GET", KatHttp3Request("GET", "https://example.com").method) }
}
