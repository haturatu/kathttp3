package dev.kathttp

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import java.util.concurrent.atomic.AtomicLong

internal class AndroidNetworkMonitor(context: Context, private val changed: (Long) -> Unit) : AutoCloseable {
    private val manager = context.applicationContext.getSystemService(ConnectivityManager::class.java)
    private val generation = AtomicLong(0)
    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = changed(generation.incrementAndGet())
        override fun onLost(network: Network) = changed(generation.incrementAndGet())
    }
    init { manager.registerDefaultNetworkCallback(callback) }
    override fun close() { manager.unregisterNetworkCallback(callback) }
}
