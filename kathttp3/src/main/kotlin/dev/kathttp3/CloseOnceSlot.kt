package dev.kathttp3

/**
 * Publishes one closeable resource to a concurrent terminal path.
 *
 * If termination wins before publication, the late resource is closed
 * immediately. If publication wins, termination closes it exactly once.
 */
internal class CloseOnceSlot<T : AutoCloseable> : AutoCloseable {
    private val lock = Any()
    private var terminal = false
    private var value: T? = null

    fun publish(resource: T): Boolean = synchronized(lock) {
        if (terminal) {
            resource.close()
            return@synchronized false
        }
        check(value == null) { "A resource is already published" }
        value = resource
        true
    }

    override fun close() {
        val resource = synchronized(lock) {
            if (terminal) return
            terminal = true
            value.also { value = null }
        }
        resource?.close()
    }
}
