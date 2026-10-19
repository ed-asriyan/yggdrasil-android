package eu.neilalexander.yggdrasil.mesh

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.ParcelUuid
import android.os.SystemClock
import android.util.Log
import androidx.annotation.RequiresApi
import java.io.DataInputStream
import java.nio.ByteBuffer
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread

private const val TAG = "MeshBle"

private const val TRANSPORT = BLE
private val SERVICE_UUID = ParcelUuid(UUID.fromString("5b1c7f3e-9a4d-4f8b-b2e6-7d0a1c9e4f21"))

// Do not dial a peer again sooner than this after a failed or closed link.
private const val BACKOFF_MS = 30_000L
// The higher node ID of a pair dials too once the peer has stayed unlinked this long
private const val FALLBACK_DIAL_MS = 30_000L
private const val CONNECT_ATTEMPTS = 3
private const val CONNECT_RETRY_MS = 1_500L

/**
 * Every node listens on an insecure L2CAP channel (no pairing, so no prompt)
 * and advertises its PSM and node ID as service data. Nodes scan for that
 * service, and the initiator of each pair (see [NearbyMesh.isInitiatorFor])
 * opens the channel; the other one does too when the peer stays unlinked, as
 * dialing fails one way only on some stacks. The opener sends its node ID
 * first, so both sides know the peer of every link. Throughput is far below Wi-Fi Aware, so a peer that is
 * already linked over Wi-Fi Aware is not dialed over BLE.
 *
 * The advertisement carries the service UUID, which scans filter on (a filter
 * every BLE stack offloads well), and the scan response its service data: the
 * 2-byte PSM and the 8-byte node ID.
 */
@SuppressLint("MissingPermission") // NearbyMesh starts this only once permissions are granted
@RequiresApi(Build.VERSION_CODES.Q)
class BleTransport(private val context: Context, private val mesh: NearbyMesh) {
    companion object {
        fun isSupported(context: Context): Boolean =
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
                context.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)
    }

    private val adapter: BluetoothAdapter? = context.getSystemService(BluetoothManager::class.java)?.adapter
    private var server: BluetoothServerSocket? = null
    private var running = false
    private var stopped = false

    /** What this transport is doing, for the diagnostics in Peers. */
    @Volatile
    var status = "starting"
        private set
    private val seen = ConcurrentHashMap.newKeySet<String>()

    private val connecting = ConcurrentHashMap.newKeySet<String>()
    // When each peer was first seen with no link to it
    private val unlinkedSince = ConcurrentHashMap<String, Long>()
    private var scanFilters: List<ScanFilter> = emptyList()
    private var scanSettings: ScanSettings? = null
    private var scanPauses = 0
    private val backoff = ConcurrentHashMap<String, Long>()

    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)) {
                BluetoothAdapter.STATE_ON -> up()
                BluetoothAdapter.STATE_TURNING_OFF, BluetoothAdapter.STATE_OFF -> down()
            }
        }
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartFailure(errorCode: Int) {
            Log.w(TAG, "Advertising failed: $errorCode")
            status = "advertising failed (error $errorCode)"
        }
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) = found(result)

        override fun onBatchScanResults(results: MutableList<ScanResult>) = results.forEach { found(it) }

        override fun onScanFailed(errorCode: Int) {
            Log.w(TAG, "Scan failed: $errorCode")
            status = "scan failed (error $errorCode)"
        }
    }

    fun summary(): String = "$status, ${seen.size} seen"

    fun start() {
        context.registerReceiver(stateReceiver, IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED))
        if (adapter?.isEnabled == true) up() else status = "Bluetooth is off"
    }

    fun stop() {
        try { context.unregisterReceiver(stateReceiver) } catch (_: Exception) {}
        synchronized(this) { stopped = true }
        down()
    }

    @Synchronized
    private fun up() {
        val adapter = adapter ?: return
        if (running || stopped) return
        try {
            val server = adapter.listenUsingInsecureL2capChannel()
            this.server = server
            startAccepting(server)

            val psm = server.psm
            val payload = ByteBuffer.allocate(2 + NODE_ID_LENGTH)
                .putShort(psm.toShort())
                .put(mesh.nodeId)
                .array()
            val settings = AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_BALANCED)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
                .setConnectable(true)
                .setTimeout(0)
                .build()
            val data = AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .setIncludeTxPowerLevel(false)
                .addServiceUuid(SERVICE_UUID)
                .build()
            val response = AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .setIncludeTxPowerLevel(false)
                .addServiceData(SERVICE_UUID, payload)
                .build()
            val advertiser = adapter.bluetoothLeAdvertiser
            if (advertiser == null) {
                status = "this device cannot advertise over BLE"
            } else {
                advertiser.startAdvertising(settings, data, response, advertiseCallback)
            }

            scanFilters = listOf(ScanFilter.Builder().setServiceUuid(SERVICE_UUID).build())
            scanSettings = ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_BALANCED)
                .build()
            scanPauses = 0
            adapter.bluetoothLeScanner?.startScan(scanFilters, scanSettings, scanCallback)

            running = true
            if (advertiser != null) status = "searching"
            Log.i(TAG, "Started on PSM $psm")
        } catch (e: Exception) {
            Log.w(TAG, "Starting failed: $e")
            status = "failed to start: $e"
            down()
        }
    }

    @Synchronized
    private fun down() {
        running = false
        if (!stopped) status = "Bluetooth is off"
        try { adapter?.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback) } catch (_: Exception) {}
        try { adapter?.bluetoothLeScanner?.stopScan(scanCallback) } catch (_: Exception) {}
        try { server?.close() } catch (_: Exception) {}
        server = null
    }

    private fun found(result: ScanResult) {
        // Without the scan response (passive scans, some stacks) the peer is not usable yet
        val data = result.scanRecord?.getServiceData(SERVICE_UUID) ?: return
        if (data.size != 2 + NODE_ID_LENGTH) return
        val buffer = ByteBuffer.wrap(data)
        val psm = buffer.short.toInt() and 0xffff
        val id = ByteArray(NODE_ID_LENGTH).also { buffer.get(it) }
        val peerId = NearbyMesh.bytesToHex(id)
        if (seen.add(peerId)) Log.i(TAG, "Found $peerId")
        if (mesh.isInitiatorFor(id)) mesh.seenNearby(peerId)
        if (mesh.hasLink(peerId)) {
            unlinkedSince.remove(peerId)
            return
        }
        val now = SystemClock.elapsedRealtime()
        val since = unlinkedSince.getOrPut(peerId) { now }
        if (!mesh.isInitiatorFor(id) && now - since < FALLBACK_DIAL_MS) return
        val until = backoff[peerId]
        if (until != null && SystemClock.elapsedRealtime() < until) return
        if (!connecting.add(peerId)) return

        thread(name = "mesh-ble-connect") {
            // Some stacks fail to connect while scanning, so the scan pauses meanwhile
            pauseScan()
            try {
                val socket = connect(result, psm, peerId)
                socket.outputStream.write(mesh.nodeId)
                socket.outputStream.flush()
                mesh.attach(peerId, TRANSPORT, true, socket, socket.inputStream, socket.outputStream) {
                    backoff[peerId] = SystemClock.elapsedRealtime() + BACKOFF_MS
                }
                status = "searching"
            } catch (e: Exception) {
                Log.w(TAG, "Connecting to $peerId failed: $e")
                status = "connecting to ${peerId.take(8)} failed: ${e.javaClass.simpleName}: ${e.message}"
                backoff[peerId] = SystemClock.elapsedRealtime() + BACKOFF_MS
            } finally {
                resumeScan()
                connecting.remove(peerId)
            }
        }
    }

    private fun connect(result: ScanResult, psm: Int, peerId: String): BluetoothSocket {
        var error: Exception? = null
        repeat(CONNECT_ATTEMPTS) { attempt ->
            if (attempt > 0) Thread.sleep(CONNECT_RETRY_MS)
            val socket = result.device.createInsecureL2capChannel(psm)
            try {
                socket.connect()
                return socket
            } catch (e: Exception) {
                Log.w(TAG, "Connecting to $peerId, attempt ${attempt + 1}: $e")
                try { socket.close() } catch (_: Exception) {}
                error = e
            }
        }
        throw error!!
    }

    @Synchronized
    private fun pauseScan() {
        if (scanPauses++ == 0 && running) {
            try { adapter?.bluetoothLeScanner?.stopScan(scanCallback) } catch (_: Exception) {}
        }
    }

    @Synchronized
    private fun resumeScan() {
        if (--scanPauses == 0 && running) {
            try { adapter?.bluetoothLeScanner?.startScan(scanFilters, scanSettings, scanCallback) } catch (_: Exception) {}
        }
    }

    private fun startAccepting(server: BluetoothServerSocket) {
        thread(name = "mesh-ble-accept") {
            while (true) {
                val socket = try { server.accept() } catch (_: Exception) { break }
                thread(name = "mesh-ble-hello") {
                    try {
                        val id = ByteArray(NODE_ID_LENGTH)
                        DataInputStream(socket.inputStream).readFully(id)
                        mesh.attach(NearbyMesh.bytesToHex(id), TRANSPORT, false, socket, socket.inputStream, socket.outputStream)
                    } catch (e: Exception) {
                        Log.w(TAG, "Inbound link failed: $e")
                        try { socket.close() } catch (_: Exception) {}
                    }
                }
            }
        }
    }
}
