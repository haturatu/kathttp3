package dev.kathttp3

/** Serializes default-network identity changes and suppresses duplicate or
 * stale onLost callbacks. Android callback ordering is preserved by the
 * platform, but close can race a callback on another thread. */
internal class NetworkIdentityTracker(
    private val changed: (generation: Long, networkHandle: Long) -> Unit,
) : AutoCloseable {
    private var generation = 0L
    private var currentHandle = 0L
    private var closed = false

    @Synchronized
    fun available(networkHandle: Long) {
        if (closed || networkHandle == 0L || networkHandle == currentHandle) return
        currentHandle = networkHandle
        changed(++generation, networkHandle)
    }

    @Synchronized
    fun lost(networkHandle: Long) {
        if (closed || networkHandle == 0L || networkHandle != currentHandle) return
        currentHandle = 0L
        changed(++generation, 0L)
    }

    @Synchronized
    override fun close() {
        closed = true
    }
}
