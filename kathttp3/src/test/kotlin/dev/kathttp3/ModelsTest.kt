package dev.kathttp3

import org.junit.Test
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import kotlin.test.assertFailsWith
import kotlin.test.assertEquals

class ModelsTest {
    @Test fun configValidation() { assertFailsWith<IllegalArgumentException> { KatHttp3ClientConfig(maxBufferedBodyBytes = 0) } }
    @Test fun streamingByteBudgetIsBounded() {
        val budget = StreamingBufferBudget(10)
        assertEquals(true, budget.tryAcquire(6))
        assertEquals(false, budget.tryAcquire(5))
        budget.release(6)
        assertEquals(0, budget.usedBytes())
    }
    @Test fun streamingDefaultsReserveConnectionCapacityForPeers() {
        val config = KatHttp3ClientConfig()
        assertEquals(1L * 1024 * 1024, config.maxStreamingBufferedBytesPerStream)
        assertEquals(16L * 1024 * 1024, config.maxStreamingBufferedBytesPerConnection)
    }
    @Test fun phaseTimeoutValidation() {
        assertFailsWith<IllegalArgumentException> { KatHttp3ClientConfig(readTimeoutMillis = 0) }
        assertEquals(10_000, KatHttp3ClientConfig().handshakeTimeoutMillis)
        assertEquals(30_000, KatHttp3ClientConfig().callTimeoutMillis)
    }
    @Test fun zeroRttIsEnabledByDefault() {
        assertEquals(true, KatHttp3ClientConfig().enable0Rtt)
        assertEquals(false, KatHttp3ClientConfig(enable0Rtt = false).enable0Rtt)
    }
    @Test fun qlogRequiresExplicitOptInAndPath() {
        assertEquals(false, KatHttp3ClientConfig().qlogEnabled)
        assertFailsWith<IllegalArgumentException> { KatHttp3ClientConfig(qlogEnabled = true) }
        assertEquals(true, KatHttp3ClientConfig(qlogEnabled = true, qlogPathPrefix = "/tmp/qlog").qlogEnabled)
    }
    @Test fun requestRequiresHttps() { assertFailsWith<IllegalArgumentException> { KatHttp3Request("GET", "http://example.com") } }
    @Test fun headerRejectsInjection() { assertFailsWith<IllegalArgumentException> { KatHttp3Header("x", "ok\r\nbad") } }
    @Test fun immutableValueBasics() { assertEquals("GET", KatHttp3Request("GET", "https://example.com").method) }
    @Test fun requestSchedulerUsesEffectiveOrigin() {
        assertEquals("https://example.com:443", OriginRequestScheduler.originOf("https://EXAMPLE.com/path"))
        assertEquals("https://example.com:8443", OriginRequestScheduler.originOf("https://example.com:8443/path"))
    }
    @Test fun requestSchedulerBoundsQueuedCalls() = runBlocking { supervisorScope {
        val scheduler = OriginRequestScheduler(1, 0, 1_000)
        val permit = scheduler.acquire("https://example.com")
        val waiting = async { scheduler.acquire("https://example.com") }
        delay(10)
        assertFailsWith<KatHttp3Exception.RequestQueueFull> { waiting.await() }
        permit.close()
        scheduler.close()
    } }
    @Test fun requestSchedulerTimesOutBeforeNativeSubmission() = runBlocking { supervisorScope {
        val scheduler = OriginRequestScheduler(1, 1, 20)
        val permit = scheduler.acquire("https://example.com")
        val waiting = async { scheduler.acquire("https://example.com") }
        assertFailsWith<KatHttp3Exception.RequestQueueTimeout> { waiting.await() }
        permit.close()
        scheduler.close()
    } }
}
