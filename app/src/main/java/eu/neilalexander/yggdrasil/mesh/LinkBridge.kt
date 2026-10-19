package eu.neilalexander.yggdrasil.mesh

import android.util.Log
import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

private const val TAG = "MeshLinkBridge"

/**
 * Splices a byte stream from a nearby transport (Wi-Fi Aware socket, BLE L2CAP
 * channel) into a TCP connection to the local Yggdrasil listener.
 *
 * The mobile bindings of yggdrasil-go have no API to add a peer over an
 * arbitrary stream, but Yggdrasil links are symmetric after the handshake: if
 * both sides connect their end of the transport to their own local listener,
 * each node sees an inbound peering and the link comes up.
 */
class LinkBridge(
    val peerId: String?,
    val transport: String,
    /** Whether we opened the transport stream. */
    val outbound: Boolean,
    private val remote: Closeable,
    private val remoteIn: InputStream,
    private val remoteOut: OutputStream,
    localPort: Int,
    private val onClosed: (LinkBridge) -> Unit,
) {
    private val closed = AtomicBoolean()
    private val local = Socket(InetAddress.getLoopbackAddress(), localPort).apply {
        tcpNoDelay = true
    }

    fun start() {
        Log.i(TAG, "Link up: $transport ${peerId ?: "?"} ${if (outbound) "outbound" else "inbound"}")
        thread(name = "mesh-$transport-up") { pump(remoteIn, local.getOutputStream()) }
        thread(name = "mesh-$transport-down") { pump(local.getInputStream(), remoteOut) }
    }

    private fun pump(from: InputStream, to: OutputStream) {
        val buf = ByteArray(16384)
        try {
            while (!closed.get()) {
                val n = from.read(buf)
                if (n < 0) break
                to.write(buf, 0, n)
                to.flush()
            }
        } catch (_: Exception) {
        }
        close()
    }

    fun close() {
        if (!closed.compareAndSet(false, true)) {
            return
        }
        Log.i(TAG, "Link down: $transport ${peerId ?: "?"} ${if (outbound) "outbound" else "inbound"}")
        try { local.close() } catch (_: Exception) {}
        try { remote.close() } catch (_: Exception) {}
        onClosed(this)
    }
}
