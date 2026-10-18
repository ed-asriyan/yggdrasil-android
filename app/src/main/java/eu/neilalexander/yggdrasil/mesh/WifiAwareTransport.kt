package eu.neilalexander.yggdrasil.mesh

import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.aware.AttachCallback
import android.net.wifi.aware.DiscoverySession
import android.net.wifi.aware.DiscoverySessionCallback
import android.net.wifi.aware.PeerHandle
import android.net.wifi.aware.PublishConfig
import android.net.wifi.aware.PublishDiscoverySession
import android.net.wifi.aware.SubscribeConfig
import android.net.wifi.aware.SubscribeDiscoverySession
import android.net.wifi.aware.WifiAwareManager
import android.net.wifi.aware.WifiAwareNetworkInfo
import android.net.wifi.aware.WifiAwareNetworkSpecifier
import android.net.wifi.aware.WifiAwareSession
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import androidx.annotation.RequiresApi
import java.net.Inet6Address
import java.net.ServerSocket
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread

private const val TAG = "MeshWifiAware"

private const val SERVICE_NAME = "yggdrasil-mesh"
private const val TRANSPORT = "wifi-aware"

// Wi-Fi Aware only lets the responder announce a port over an encrypted data
// path, so the data path needs a passphrase. It is not a secret: Yggdrasil
// authenticates and encrypts everything end to end on its own.
private const val PASSPHRASE = "yggdrasil-mesh-link"

private const val NETWORK_TIMEOUT_MS = 30_000
private const val RETRY_DELAY_MS = 10_000L
private const val RESUBSCRIBE_DELAY_MS = 5 * 60_000L
private const val MAX_ATTEMPTS = 3

/**
 * Every node both publishes and subscribes to [SERVICE_NAME], carrying its node
 * ID as service-specific info. When the subscriber of a pair is the initiator
 * (see [NearbyMesh.isInitiatorFor]) it messages its node ID to the publisher,
 * and both sides request a NAN data path: the publisher as responder, with a
 * TCP port, and the subscriber as initiator, which connects to that port over
 * the peer's link-local IPv6 address.
 */
@SuppressLint("MissingPermission") // NearbyMesh starts this only once permissions are granted
@RequiresApi(Build.VERSION_CODES.Q)
class WifiAwareTransport(private val context: Context, private val mesh: NearbyMesh) {
    companion object {
        fun isSupported(context: Context): Boolean =
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
                context.packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI_AWARE)
    }

    private val manager = context.getSystemService(WifiAwareManager::class.java)
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val handlerThread = HandlerThread("mesh-wifi-aware").apply { start() }
    private val handler = Handler(handlerThread.looper)

    private var session: WifiAwareSession? = null
    private var publishSession: PublishDiscoverySession? = null
    private var subscribeSession: SubscribeDiscoverySession? = null
    private var server: ServerSocket? = null
    private var stopped = false
    private var messageId = 0

    // Data path requests we hold, by peer node ID. Releasing one tears the data path down.
    private val initiated = ConcurrentHashMap<String, ConnectivityManager.NetworkCallback>()
    private val responded = ConcurrentHashMap<String, ConnectivityManager.NetworkCallback>()
    private val failedAttempts = HashMap<String, Int>()

    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            handler.post {
                if (manager.isAvailable) attach() else detach()
            }
        }
    }

    fun start() {
        context.registerReceiver(stateReceiver, IntentFilter(WifiAwareManager.ACTION_WIFI_AWARE_STATE_CHANGED))
        handler.post {
            server = ServerSocket(0).also { startAccepting(it) }
            if (manager.isAvailable) attach()
        }
    }

    fun stop() {
        try { context.unregisterReceiver(stateReceiver) } catch (_: Exception) {}
        handler.post {
            stopped = true
            detach()
            try { server?.close() } catch (_: Exception) {}
            server = null
            handlerThread.quitSafely()
        }
    }

    private fun attach() {
        if (stopped || session != null) return
        manager.attach(object : AttachCallback() {
            override fun onAttached(s: WifiAwareSession) {
                if (stopped) {
                    s.close()
                    return
                }
                Log.i(TAG, "Attached")
                session = s
                publish()
                subscribe()
            }

            override fun onAttachFailed() {
                Log.w(TAG, "Attach failed, retrying")
                handler.postDelayed({ attach() }, RETRY_DELAY_MS)
            }
        }, handler)
    }

    private fun detach() {
        handler.removeCallbacksAndMessages(null)
        (initiated.values + responded.values).forEach { release(it) }
        initiated.clear()
        responded.clear()
        failedAttempts.clear()
        publishSession?.close()
        publishSession = null
        subscribeSession?.close()
        subscribeSession = null
        session?.close()
        session = null
    }

    private fun publish() {
        val config = PublishConfig.Builder()
            .setServiceName(SERVICE_NAME)
            .setServiceSpecificInfo(mesh.nodeId)
            .build()
        session?.publish(config, object : DiscoverySessionCallback() {
            override fun onPublishStarted(s: PublishDiscoverySession) {
                publishSession = s
            }

            override fun onMessageReceived(peer: PeerHandle, message: ByteArray) {
                if (message.size != NODE_ID_LENGTH) return
                respond(peer, NearbyMesh.bytesToHex(message))
            }

            override fun onSessionTerminated() {
                publishSession = null
            }
        }, handler)
    }

    private fun subscribe() {
        val config = SubscribeConfig.Builder()
            .setServiceName(SERVICE_NAME)
            .build()
        session?.subscribe(config, object : DiscoverySessionCallback() {
            override fun onSubscribeStarted(s: SubscribeDiscoverySession) {
                subscribeSession = s
                scheduleResubscribe()
            }

            override fun onServiceDiscovered(peer: PeerHandle, info: ByteArray, matchFilter: List<ByteArray>) {
                if (info.size != NODE_ID_LENGTH || !mesh.isInitiatorFor(info)) return
                initiate(peer, NearbyMesh.bytesToHex(info))
            }

            override fun onSessionTerminated() {
                subscribeSession = null
            }
        }, handler)
    }

    // A subscribe session reports each peer once, so a peer that left and came
    // back is found only by a new session. Restart it while it holds no links.
    private fun scheduleResubscribe() {
        handler.postDelayed({
            if (initiated.isEmpty() && subscribeSession != null) {
                subscribeSession?.close()
                subscribeSession = null
                subscribe()
            } else {
                scheduleResubscribe()
            }
        }, RESUBSCRIBE_DELAY_MS)
    }

    private fun initiate(peer: PeerHandle, peerId: String) {
        val discovery = subscribeSession ?: return
        if (initiated.containsKey(peerId) || mesh.hasLink(peerId, TRANSPORT)) return
        discovery.sendMessage(peer, messageId++, mesh.nodeId)

        val specifier = WifiAwareNetworkSpecifier.Builder(discovery, peer)
            .setPskPassphrase(PASSPHRASE)
            .build()
        val callback = object : ConnectivityManager.NetworkCallback() {
            private var connecting = false

            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                val info = capabilities.transportInfo as? WifiAwareNetworkInfo ?: return
                val address = info.peerIpv6Addr ?: return
                if (connecting || info.port <= 0) return
                connecting = true
                thread(name = "mesh-wifi-aware-connect") { connect(network, address, info.port, peerId, this) }
            }

            override fun onLost(network: Network) = retry(peer, peerId, this)
            override fun onUnavailable() = retry(peer, peerId, this)
        }
        initiated[peerId] = callback
        request(specifier, callback)
    }

    private fun connect(
        network: Network,
        address: Inet6Address,
        port: Int,
        peerId: String,
        callback: ConnectivityManager.NetworkCallback,
    ) {
        try {
            val socket = network.socketFactory.createSocket(address, port)
            socket.tcpNoDelay = true
            handler.post { failedAttempts.remove(peerId) }
            mesh.attach(peerId, TRANSPORT, socket, socket.getInputStream(), socket.getOutputStream()) {
                handler.post { if (initiated.remove(peerId, callback)) release(callback) }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Connecting to $peerId failed: $e")
            handler.post { if (initiated.remove(peerId, callback)) release(callback) }
        }
    }

    private fun retry(peer: PeerHandle, peerId: String, callback: ConnectivityManager.NetworkCallback) {
        handler.post {
            if (!initiated.remove(peerId, callback)) return@post
            release(callback)
            // The peer handle stays valid while the peer is in range. Once it is
            // gone, give up: the resubscribe finds it again when it comes back.
            val attempts = (failedAttempts[peerId] ?: 0) + 1
            if (attempts >= MAX_ATTEMPTS) {
                failedAttempts.remove(peerId)
                return@post
            }
            failedAttempts[peerId] = attempts
            handler.postDelayed({ initiate(peer, peerId) }, RETRY_DELAY_MS)
        }
    }

    private fun respond(peer: PeerHandle, peerId: String) {
        val discovery = publishSession ?: return
        val port = server?.localPort ?: return
        // A new request from a known peer means it restarted: drop the stale data path.
        responded.remove(peerId)?.let { release(it) }

        val specifier = WifiAwareNetworkSpecifier.Builder(discovery, peer)
            .setPskPassphrase(PASSPHRASE)
            .setPort(port)
            .build()
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onLost(network: Network) = drop()
            override fun onUnavailable() = drop()

            private fun drop() {
                handler.post { if (responded.remove(peerId, this)) release(this) }
            }
        }
        responded[peerId] = callback
        request(specifier, callback)
    }

    private fun request(specifier: WifiAwareNetworkSpecifier, callback: ConnectivityManager.NetworkCallback) {
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI_AWARE)
            .setNetworkSpecifier(specifier)
            .build()
        try {
            connectivity.requestNetwork(request, callback, NETWORK_TIMEOUT_MS)
        } catch (e: Exception) {
            Log.w(TAG, "Data path request failed: $e")
        }
    }

    private fun release(callback: ConnectivityManager.NetworkCallback) {
        try { connectivity.unregisterNetworkCallback(callback) } catch (_: Exception) {}
    }

    private fun startAccepting(server: ServerSocket) {
        thread(name = "mesh-wifi-aware-accept") {
            while (!server.isClosed) {
                val socket = try { server.accept() } catch (_: Exception) { break }
                // Only peers on a Wi-Fi Aware data path may link through here.
                if (!socket.inetAddress.isLinkLocalAddress) {
                    socket.close()
                    continue
                }
                socket.tcpNoDelay = true
                mesh.attach(null, TRANSPORT, socket, socket.getInputStream(), socket.getOutputStream())
            }
        }
    }
}
