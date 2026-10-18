package eu.neilalexander.yggdrasil

/**
 * A Yggdrasil-ng node, run by libyggdrasil.so (libs/yggdrasil-ng-jni).
 * Not usable again after [stop].
 */
class Yggdrasil {
    private var handle = 0L

    /**
     * Starts the node with [config], in the JSON format of yggdrasil-go.
     * [interfaces] lists the interfaces for multicast discovery as JSON:
     * `[{"Name": "wlan0", "Index": 30, "Addrs": ["fe80::1"]}]`.
     */
    fun startJSON(config: ByteArray, interfaces: String = "[]") {
        handle = nativeStart(String(config, Charsets.UTF_8), interfaces)
    }

    fun stop() {
        val h = handle
        if (h != 0L) {
            handle = 0L
            nativeStop(h)
        }
    }

    fun sendBuffer(buf: ByteArray, length: Long) = nativeSend(handle, buf, length.toInt())

    /** Blocks until a packet arrives; throws once the node is stopped. */
    fun recvBuffer(buf: ByteArray): Long {
        val h = handle
        val n = if (h != 0L) nativeRecv(h, buf) else -1
        if (n < 0) throw IllegalStateException("Yggdrasil is stopped")
        return n.toLong()
    }

    fun retryPeersNow() = nativeRetryPeersNow(handle)

    fun updateNetworkInterfaces(interfaces: String) = nativeUpdateNetworkInterfaces(handle, interfaces)

    // Empty (or "[]") once the node is stopped
    val addressString: String get() = nativeAddress(handle) ?: ""
    val subnetString: String get() = nativeSubnet(handle) ?: ""
    val publicKeyString: String get() = nativePublicKey(handle) ?: ""
    val mtu: Long get() = nativeMtu(handle)
    val peersJSON: String get() = nativePeers(handle) ?: "[]"
    val treeJSON: String get() = nativeTree(handle) ?: "[]"
    val routingEntries: Long get() = nativeRoutingEntries(handle)

    companion object {
        init {
            System.loadLibrary("yggdrasil")
        }

        fun generateConfigJSON(): ByteArray = nativeGenerateConfig().toByteArray(Charsets.UTF_8)

        fun getVersion(): String = nativeVersion()

        @JvmStatic private external fun nativeStart(config: String, interfaces: String): Long
        @JvmStatic private external fun nativeStop(handle: Long)
        @JvmStatic private external fun nativeSend(handle: Long, buf: ByteArray, len: Int)
        @JvmStatic private external fun nativeRecv(handle: Long, buf: ByteArray): Int
        @JvmStatic private external fun nativeAddress(handle: Long): String?
        @JvmStatic private external fun nativeSubnet(handle: Long): String?
        @JvmStatic private external fun nativePublicKey(handle: Long): String?
        @JvmStatic private external fun nativeMtu(handle: Long): Long
        @JvmStatic private external fun nativePeers(handle: Long): String?
        @JvmStatic private external fun nativeTree(handle: Long): String?
        @JvmStatic private external fun nativeRoutingEntries(handle: Long): Long
        @JvmStatic private external fun nativeRetryPeersNow(handle: Long)
        @JvmStatic private external fun nativeUpdateNetworkInterfaces(handle: Long, interfaces: String)
        @JvmStatic private external fun nativeGenerateConfig(): String
        @JvmStatic private external fun nativeVersion(): String
    }
}
