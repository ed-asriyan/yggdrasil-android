package eu.neilalexander.yggdrasil.mesh

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream
import java.util.Collections

private const val TAG = "NearbyMesh"

const val PREF_KEY_NEARBY_MESH = "nearby_mesh"

const val WIFI_AWARE = "wifi-aware"
const val BLE = "ble"

// Length of the node ID that nearby transports advertise: a prefix of the
// Yggdrasil public key, short enough to fit a BLE advertisement.
const val NODE_ID_LENGTH = 8

/**
 * Finds nearby devices running this app and peers Yggdrasil with them, with no
 * user interaction: Wi-Fi Aware when the device supports it, BLE L2CAP as a
 * fallback. Yggdrasil then routes over these links, so devices out of range of
 * each other still reach each other through the ones in between.
 *
 * Of any two nodes, the one with the lower node ID opens the link, so every
 * pair gets one link per transport and the opener can drop duplicates.
 */
class NearbyMesh(
    private val context: Context,
    publicKeyHex: String,
    private val localPort: Int,
) {
    val nodeId: ByteArray = hexToBytes(publicKeyHex).copyOf(NODE_ID_LENGTH)

    private val bridges = Collections.synchronizedSet(mutableSetOf<LinkBridge>())
    @Volatile
    private var wifiAware: WifiAwareTransport? = null
    private var ble: BleTransport? = null
    @Volatile
    private var running = false

    /** Starts the transports that can run and are not running yet. Safe to call repeatedly. */
    @Synchronized
    fun refresh() {
        running = true
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            Log.i(TAG, "Nearby mesh needs Android 10+")
            return
        }
        if (wifiAware == null && WifiAwareTransport.isSupported(context) && hasWifiAwarePermissions(context)) {
            wifiAware = WifiAwareTransport(context, this).also { it.start() }
        }
        if (ble == null && BleTransport.isSupported(context) && hasBlePermissions(context)) {
            ble = BleTransport(context, this).also { it.start() }
        }
    }

    @Synchronized
    fun stop() {
        running = false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            wifiAware?.stop()
            ble?.stop()
        }
        wifiAware = null
        ble = null
        synchronized(bridges) { bridges.toList() }.forEach { it.close() }
    }

    fun isInitiatorFor(peerId: ByteArray): Boolean {
        for (i in 0 until NODE_ID_LENGTH) {
            val a = nodeId[i].toInt() and 0xff
            val b = peerId[i].toInt() and 0xff
            if (a != b) return a < b
        }
        return false
    }

    /** Whether we hold an outbound link to the peer, over the given transport or over any. */
    fun hasLink(peerId: String, transport: String? = null): Boolean = synchronized(bridges) {
        bridges.any { it.peerId == peerId && (transport == null || it.transport == transport) }
    }

    /** A peer that BLE sees: look for it over Wi-Fi Aware too, unless linked there already. */
    fun seenNearby(peerId: String) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q || hasLink(peerId, WIFI_AWARE)) return
        wifiAware?.rediscover(peerId)
    }

    /**
     * Bridges a connected transport stream into the local Yggdrasil node.
     * [peerId] is known on the opening side only. Returns false and closes the
     * stream when the local listener refuses or the mesh is stopped.
     */
    fun attach(
        peerId: String?,
        transport: String,
        remote: Closeable,
        input: InputStream,
        output: OutputStream,
        onClosed: () -> Unit = {},
    ): Boolean {
        val bridge = try {
            LinkBridge(peerId, transport, remote, input, output, localPort) {
                bridges.remove(it)
                onClosed()
            }
        } catch (e: Exception) {
            Log.w(TAG, "Local Yggdrasil listener unreachable on port $localPort: $e")
            try { remote.close() } catch (_: Exception) {}
            onClosed()
            return false
        }
        if (!running) {
            bridge.close()
            return false
        }
        bridges.add(bridge)
        bridge.start()
        // Yggdrasil does not prefer the faster of two links to the same peer,
        // so a Wi-Fi Aware link replaces a BLE one; BLE comes back if it drops.
        if (transport == WIFI_AWARE && peerId != null) {
            synchronized(bridges) { bridges.filter { it.peerId == peerId && it.transport == BLE } }
                .forEach { it.close() }
        }
        return true
    }

    companion object {
        fun wifiAwarePermissions(): Array<String> = when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU -> arrayOf(Manifest.permission.NEARBY_WIFI_DEVICES)
            else -> arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }

        fun blePermissions(): Array<String> = when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> arrayOf(
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_ADVERTISE,
                Manifest.permission.BLUETOOTH_CONNECT,
            )
            else -> arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }

        /** Runtime permissions the nearby mesh still needs, empty when all are granted. */
        fun missingPermissions(context: Context): Array<String> {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return arrayOf()
            return (wifiAwarePermissions() + blePermissions()).distinct()
                .filter { !granted(context, it) }
                .toTypedArray()
        }

        fun hasWifiAwarePermissions(context: Context) = wifiAwarePermissions().all { granted(context, it) }

        fun hasBlePermissions(context: Context) = blePermissions().all { granted(context, it) }

        private fun granted(context: Context, permission: String) =
            ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED

        fun bytesToHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

        private fun hexToBytes(hex: String): ByteArray =
            ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}
