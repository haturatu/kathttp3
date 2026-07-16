package dev.kathttp3

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network

internal class AndroidNetworkMonitor(
    context: Context,
    changed: (generation: Long, networkHandle: Long) -> Unit,
) : AutoCloseable {
    private val manager = context.applicationContext.getSystemService(ConnectivityManager::class.java)
    private val tracker = NetworkIdentityTracker(changed)
    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = tracker.available(network.networkHandle)
        override fun onLost(network: Network) = tracker.lost(network.networkHandle)
    }
    init {
        manager.registerDefaultNetworkCallback(callback)
        // The callback normally reports the current default immediately. The
        // explicit snapshot closes the small registration/request race and is
        // deduplicated if onAvailable already ran.
        manager.activeNetwork?.let { tracker.available(it.networkHandle) }
    }
    override fun close() {
        tracker.close()
        manager.unregisterNetworkCallback(callback)
    }
}
