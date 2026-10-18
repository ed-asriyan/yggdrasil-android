package eu.neilalexander.yggdrasil

import android.content.Context
import androidx.preference.PreferenceManager
import org.json.JSONArray
import org.json.JSONObject

const val KEY_CLEARNET_EXITS = "clearnet_exits"

/**
 * Clearnet (the Internet) through YggMesh exit nodes, with Crypto-Key Routing.
 *
 * All IPv4 of the device goes over Yggdrasil to the public key of the exit,
 * from the device's own IPv4 address: 100.64.0.0/10 plus the last 22 bits of
 * its public key. The exit derives the same address from the key and accepts
 * the device's packets from that address only, as it does for YggMesh routers
 * (see YggMesh-exit-node), so the exit's owner needs the device's public key.
 */
object Clearnet {
    private val KEY = Regex("^[0-9a-f]{64}$")

    /** Public keys of the configured exits, in order of preference. */
    fun exits(context: Context): List<String> {
        val preferences = PreferenceManager.getDefaultSharedPreferences(context)
        return parseExits(preferences.getString(KEY_CLEARNET_EXITS, "") ?: "")
    }

    fun parseExits(text: String): List<String> =
        text.lowercase().split(Regex("[\\s,]+")).filter { KEY.matches(it) }.distinct()

    /** The exit that CKR sends IPv4 to, or null when clearnet over Yggdrasil is off. */
    fun activeExit(context: Context): String? = exits(context).firstOrNull()

    /** The device's IPv4 address for exits, the same as YggMesh routers derive. */
    fun ipv4ForKey(publicKey: String): String {
        val n = publicKey.substring(58, 64).toInt(16) and 0x3fffff
        return "100.${64 + (n shr 16)}.${(n shr 8) and 255}.${n and 255}"
    }

    /** The TunnelRouting section of the node config, routing all IPv4 to [exit]. */
    fun tunnelRouting(publicKey: String, exit: String): JSONObject = JSONObject()
        .put("Enable", true)
        .put("IPAddresses", JSONArray().put(ipv4ForKey(publicKey) + "/32"))
        // "~": CKR only, the routes are VpnService's
        .put("RemoteSubnets", JSONObject().put(exit, JSONArray().put("~0.0.0.0/0")))

    // Resolvers reached through the exit, for the clearnet names
    val dnsServers = listOf("1.1.1.1", "8.8.8.8")
}
