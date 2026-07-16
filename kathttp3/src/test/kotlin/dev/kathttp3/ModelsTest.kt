package dev.kathttp3

import org.junit.Test
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.toList
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
    @Test fun streamingResponseQueuePreservesBodyOrderAndDrainsBeforeCompletion() = runBlocking {
        val budget = StreamingBufferBudget(64)
        val queue = StreamingResponseQueue(64, budget)
        assertEquals(true, queue.offer(KatHttp3StreamEvent.Body(byteArrayOf(1, 2))))
        assertEquals(true, queue.offer(KatHttp3StreamEvent.Body(byteArrayOf(3))))
        assertEquals(true, queue.offer(KatHttp3StreamEvent.Body(byteArrayOf(4, 5, 6))))
        queue.finish()

        val bytes = queue.events.toList().flatMap { event ->
            (event as KatHttp3StreamEvent.Body).bytes.toList()
        }
        assertEquals(listOf<Byte>(1, 2, 3, 4, 5, 6), bytes)
        assertEquals(0, queue.bufferedBytes())
        assertEquals(0, budget.usedBytes())
    }
    @Test fun streamingResponseQueueRejectsOverflowWithoutLeakingBudget() = runBlocking {
        val budget = StreamingBufferBudget(5)
        val queue = StreamingResponseQueue(4, budget)
        assertEquals(true, queue.offer(KatHttp3StreamEvent.Body(byteArrayOf(1, 2, 3))))
        assertEquals(false, queue.offer(KatHttp3StreamEvent.Body(byteArrayOf(4, 5))))
        queue.finish()
        assertEquals(listOf<Byte>(1, 2, 3), queue.events.toList().flatMap {
            (it as KatHttp3StreamEvent.Body).bytes.toList()
        })
        assertEquals(0, budget.usedBytes())
    }
    @Test fun streamingResponseQueueAbortDropsChunksAndReleasesBudget() = runBlocking {
        val budget = StreamingBufferBudget(16)
        val queue = StreamingResponseQueue(16, budget)
        assertEquals(true, queue.offer(KatHttp3StreamEvent.Body(byteArrayOf(1, 2, 3))))
        queue.abort()
        assertEquals(emptyList(), queue.events.toList())
        assertEquals(0, budget.usedBytes())
    }
    @Test fun phaseTimeoutValidation() {
        assertFailsWith<IllegalArgumentException> { KatHttp3ClientConfig(readTimeoutMillis = 0) }
        assertEquals(10_000, KatHttp3ClientConfig().handshakeTimeoutMillis)
        assertEquals(30_000, KatHttp3ClientConfig().callTimeoutMillis)
    }
    @Test fun retryRejectsAmbiguousAndLocalTimeouts() {
        val policy = KatHttp3RetryPolicy()
        val request = KatHttp3Request("GET", "https://example.com")
        assertEquals(true, policy.canRetry(request, KatHttp3Exception.Timeout(KatHttp3TimeoutPhase.Connect)))
        assertEquals(false, policy.canRetry(request, KatHttp3Exception.Timeout(KatHttp3TimeoutPhase.Read)))
        assertEquals(false, policy.canRetry(request, KatHttp3Exception.ConsumerStallTimeout()))
    }
    @Test fun zeroRttIsEnabledByDefault() {
        assertEquals(true, KatHttp3ClientConfig().enable0Rtt)
        assertEquals(false, KatHttp3ClientConfig(enable0Rtt = false).enable0Rtt)
    }
    @Test fun qlogDestinationsRequireExplicitOptIn() {
        assertEquals(false, KatHttp3ClientConfig().qlogEnabled)
        assertEquals(true, KatHttp3ClientConfig(qlogEnabled = true).qlogEnabled)
        assertEquals(true, KatHttp3ClientConfig(qlogEnabled = true, qlogPathPrefix = "/tmp/qlog").qlogEnabled)
        assertFailsWith<IllegalArgumentException> { KatHttp3ClientConfig(qlogPathPrefix = "/tmp/qlog") }
        assertFailsWith<IllegalArgumentException> { KatHttp3ClientConfig(qlogLogcatEnabled = true) }
        assertEquals(true, KatHttp3ClientConfig(qlogEnabled = true, qlogPathPrefix = "/tmp/qlog", qlogLogcatEnabled = true).qlogLogcatEnabled)
    }
    @Test fun requestRequiresHttps() { assertFailsWith<IllegalArgumentException> { KatHttp3Request("GET", "http://example.com") } }
    @Test fun headerRejectsInjection() { assertFailsWith<IllegalArgumentException> { KatHttp3Header("x", "ok\r\nbad") } }
    @Test fun headerAcceptsConventionalMixedCaseName() {
        assertEquals("Content-Type", KatHttp3Header("Content-Type", "application/json").name)
    }
    @Test fun immutableValueBasics() { assertEquals("GET", KatHttp3Request("GET", "https://example.com").method) }
    @Test fun requestPriorityValidatesRfc9218Urgency() {
        assertFailsWith<IllegalArgumentException> { KatHttp3RequestPriority(urgency = -1) }
        assertFailsWith<IllegalArgumentException> { KatHttp3RequestPriority(urgency = 8) }
    }
    @Test fun networkIdentityTrackerSuppressesStaleAndPostCloseCallbacks() {
        val changes = mutableListOf<Pair<Long, Long>>()
        val tracker = NetworkIdentityTracker { generation, handle -> changes += generation to handle }
        tracker.available(100)
        tracker.available(100)
        tracker.lost(99)
        tracker.available(200)
        tracker.lost(100)
        tracker.lost(200)
        tracker.close()
        tracker.available(300)
        assertEquals(listOf(1L to 100L, 2L to 200L, 3L to 0L), changes)
    }
    @Test fun retryPolicyTreatsNetworkLossAsConnectionFailure() {
        val policy = KatHttp3RetryPolicy()
        assertEquals(
            true,
            policy.canRetry(
                KatHttp3Request("GET", "https://example.com"),
                KatHttp3Exception.NetworkLost(),
            ),
        )
        assertEquals(
            false,
            policy.canRetry(
                KatHttp3Request("POST", "https://example.com"),
                KatHttp3Exception.NetworkLost(),
            ),
        )
    }
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
    @Test fun requestSchedulerAdmitsHigherUrgencyFirst() = runBlocking { supervisorScope {
        val scheduler = OriginRequestScheduler(1, 4, 1_000)
        val active = scheduler.acquire("https://example.com")
        val order = mutableListOf<String>()
        val low = async {
            scheduler.acquire(
                "https://example.com",
                KatHttp3RequestPriority(urgency = 7),
            ).use { order += "low" }
        }
        delay(10)
        val high = async {
            scheduler.acquire(
                "https://example.com",
                KatHttp3RequestPriority(urgency = 0),
            ).use { order += "high" }
        }
        delay(10)
        active.close()
        high.await()
        low.await()
        assertEquals(listOf("high", "low"), order)
        scheduler.close()
    } }
}
