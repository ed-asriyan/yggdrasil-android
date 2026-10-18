//! JNI bindings of Yggdrasil-ng for `eu.neilalexander.yggdrasil.Yggdrasil`.
//!
//! The app keeps its configuration in the JSON format of yggdrasil-go (the
//! keys are compatible), and the node is converted to a Yggdrasil-ng config
//! on start. Packets from and to the VpnService TUN pass through the
//! ReadWriteCloser of the node, which also does Crypto-Key Routing.

#[cfg(target_os = "android")]
use std::ffi::CString;
use std::io::Write;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use ed25519_dalek::SigningKey;
use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jint, jlong, jstring};
use serde_json::{Value, json};
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;
use yggdrasil::config::{Config, MulticastInterfaceConfig, TunnelRoutingConfig};
use yggdrasil::core::Core;
use yggdrasil::ipv6rwc::ReadWriteCloser;
use yggdrasil::multicast::NetworkInterface;

/// Version of the Yggdrasil-ng revision in Cargo.toml.
const NG_VERSION: &str = "0.3.1";

struct Node {
    core: Arc<Core>,
    rwc: Arc<ReadWriteCloser>,
    stop: CancellationToken,
}

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        init_logging();
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("yggdrasil")
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}

// ── Logging to logcat ────────────────────────────────────────────────────

struct LogcatWriter;

impl Write for LogcatWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        let text = text.trim_end();
        #[cfg(not(target_os = "android"))]
        eprintln!("{text}");
        #[cfg(target_os = "android")]
        if !text.is_empty() {
            let tag = c"Yggdrasil";
            let msg = CString::new(text.replace('\0', "")).unwrap_or_default();
            unsafe {
                android_log_sys::__android_log_write(
                    android_log_sys::LogPriority::INFO as i32,
                    tag.as_ptr(),
                    msg.as_ptr(),
                );
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .with_ansi(false)
        .without_time()
        .with_target(false)
        .with_writer(|| LogcatWriter)
        .try_init();
}

// ── Config ───────────────────────────────────────────────────────────────

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// Converts the app's config (yggdrasil-go JSON keys) to a Yggdrasil-ng config.
fn config_from_json(json: &Value) -> Result<Config, String> {
    let mut config = Config::default();
    config.private_key = json["PrivateKey"].as_str().unwrap_or_default().to_string();
    config.peers = strings(&json["Peers"]);
    config.listen = strings(&json["Listen"]);
    config.allowed_public_keys = strings(&json["AllowedPublicKeys"]);
    config.admin_listen = String::new();
    config.if_name = "none".to_string();
    config.node_info_privacy = json["NodeInfoPrivacy"].as_bool().unwrap_or(false);
    if let Some(info) = json.get("NodeInfo").filter(|v| v.is_object()) {
        config.node_info = toml::Value::try_from(info).map_err(|e| format!("NodeInfo: {e}"))?;
    }
    config.multicast_interfaces = json["MulticastInterfaces"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|i| i.is_object())
                .map(|i| MulticastInterfaceConfig {
                    // yggdrasil-go matches interfaces with a regex, Yggdrasil-ng with a glob
                    filter: match i["Regex"].as_str().unwrap_or(".*") {
                        ".*" => "*".to_string(),
                        other => other.to_string(),
                    },
                    beacon: i["Beacon"].as_bool().unwrap_or(true),
                    listen: i["Listen"].as_bool().unwrap_or(true),
                    port: i["Port"].as_u64().unwrap_or(0) as u16,
                    priority: i["Priority"].as_u64().unwrap_or(0) as u8,
                    password: i["Password"].as_str().unwrap_or_default().to_string(),
                })
                .collect()
        })
        .unwrap_or_default();

    // Crypto-Key Routing, set by the app on start, never stored in the config file
    let tunnel = &json["TunnelRouting"];
    let mut routing = TunnelRoutingConfig::default();
    routing.enable = tunnel["Enable"].as_bool().unwrap_or(false);
    routing.install_system_routes = false;
    routing.ip_addresses = strings(&tunnel["IPAddresses"]);
    if let Some(subnets) = tunnel["RemoteSubnets"].as_object() {
        for (key, cidrs) in subnets {
            routing.remote_subnets.insert(key.to_lowercase(), strings(cidrs));
        }
    }
    config.tunnel_routing = routing;
    Ok(config)
}

fn generate_config() -> Value {
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    json!({
        "PrivateKey": hex::encode(key.to_keypair_bytes()),
        "Peers": [],
        "Listen": [],
        "AllowedPublicKeys": [],
        "AdminListen": "none",
        "IfName": "none",
        "IfMTU": 65535,
        "NodeInfoPrivacy": false,
        "NodeInfo": {},
        "MulticastInterfaces": [
            { "Regex": ".*", "Beacon": true, "Listen": true, "Port": 0, "Priority": 0, "Password": "" }
        ],
    })
}

fn start(config_json: &str, interfaces_json: &str) -> Result<Node, String> {
    let json: Value = serde_json::from_str(config_json).map_err(|e| format!("config: {e}"))?;
    let config = config_from_json(&json)?;
    let signing_key = config.signing_key()?;
    check_tunnel_routing(&config.tunnel_routing, &signing_key)?;
    let rt = runtime();

    rt.block_on(async {
        let core = Core::new(signing_key, config.clone());
        core.init_links().await;
        core.start().await;

        let rwc = ReadWriteCloser::new(core.clone(), core.mtu(), Some(&config.tunnel_routing), None);
        core.set_path_notify(rwc.clone());

        let stop = CancellationToken::new();
        // Peers' keys are known from the handshake: seed them so that the first
        // packets to a direct peer need no lookup (as the Yggdrasil-ng daemon does).
        {
            let core = core.clone();
            let rwc = rwc.clone();
            let stop = stop.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(2));
                loop {
                    tokio::select! {
                        _ = stop.cancelled() => break,
                        _ = ticker.tick() => {
                            for key in core.get_peer_keys().await {
                                rwc.update_key(key).await;
                            }
                        }
                    }
                }
            });
        }

        // Multicast uses these interfaces instead of getifaddrs() from its start on
        let interfaces = interfaces_from_json(interfaces_json);
        if !interfaces.is_empty() {
            core.update_network_interfaces(interfaces);
        }
        if let Err(e) = core.start_multicast().await {
            tracing::warn!("Multicast peer discovery disabled: {}", e);
        }
        tracing::info!("Your IPv6 address is {}", core.address());
        tracing::info!("Your public key is {}", hex::encode(core.public_key()));
        Ok(Node { core, rwc, stop })
    })
}

/// ReadWriteCloser panics on a CKR config it rejects: check it beforehand.
fn check_tunnel_routing(config: &TunnelRoutingConfig, key: &SigningKey) -> Result<(), String> {
    if !config.enable {
        return Ok(());
    }
    yggdrasil::ckr::CryptoKey::new(config, &key.verifying_key().to_bytes())
        .map(|_| ())
        .map_err(|e| format!("tunnel routing: {e}"))
}

fn peers_json(node: &Node) -> String {
    let peers = runtime().block_on(node.core.get_peers());
    let list: Vec<Value> = peers
        .iter()
        .map(|p| {
            let ip = if p.up {
                yggdrasil::address::addr_for_key(&p.key).to_string()
            } else {
                String::new()
            };
            json!({
                "URI": p.uri,
                "Up": p.up,
                "Inbound": p.inbound,
                "IP": ip,
                "Key": if p.up { hex::encode(p.key) } else { String::new() },
                "Priority": p.priority,
                "RXBytes": p.rx_bytes,
                "TXBytes": p.tx_bytes,
                "Uptime": p.uptime_secs,
                "Latency": p.latency_ms,
                "Cost": p.cost,
                "LastError": p.last_error.clone().unwrap_or_default(),
            })
        })
        .collect();
    Value::Array(list).to_string()
}

fn tree_json(node: &Node) -> String {
    let tree = runtime().block_on(node.core.get_tree());
    let list: Vec<Value> = tree
        .iter()
        .map(|t| {
            json!({
                "PublicKey": hex::encode(t.key),
                "IP": yggdrasil::address::addr_for_key(&t.key).to_string(),
                "Parent": hex::encode(t.parent),
                "Sequence": t.sequence,
            })
        })
        .collect();
    Value::Array(list).to_string()
}

/// Parses `[{"Name": "wlan0", "Index": 30, "Addrs": ["fe80::1"]}]`.
fn interfaces_from_json(text: &str) -> Vec<NetworkInterface> {
    let json: Value = serde_json::from_str(text).unwrap_or(Value::Null);
    json.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|i| {
                    Some(NetworkInterface {
                        name: i["Name"].as_str()?.to_string(),
                        index: i["Index"].as_u64()? as u32,
                        addrs: strings(&i["Addrs"]).iter().filter_map(|a| a.parse().ok()).collect(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

// ── JNI ──────────────────────────────────────────────────────────────────

// Running nodes by handle. The TUN threads may still be in a call when the
// node is stopped, so every call holds its own reference to the node.
fn nodes() -> &'static Mutex<HashMap<jlong, Arc<Node>>> {
    static NODES: OnceLock<Mutex<HashMap<jlong, Arc<Node>>>> = OnceLock::new();
    NODES.get_or_init(Default::default)
}

fn node(handle: jlong) -> Option<Arc<Node>> {
    nodes().lock().unwrap().get(&handle).cloned()
}

fn java_string(env: &mut JNIEnv, s: &str) -> jstring {
    env.new_string(s).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

fn throw(env: &mut JNIEnv, message: &str) {
    let _ = env.throw_new("java/lang/IllegalStateException", message);
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_eu_neilalexander_yggdrasil_Yggdrasil_nativeStart(
    mut env: JNIEnv,
    _: JClass,
    config: JString,
    interfaces: JString,
) -> jlong {
    let config: String = match env.get_string(&config) {
        Ok(s) => s.into(),
        Err(e) => {
            throw(&mut env, &format!("config: {e}"));
            return 0;
        }
    };
    let interfaces: String = env.get_string(&interfaces).map(Into::into).unwrap_or_default();
    static NEXT_HANDLE: AtomicI64 = AtomicI64::new(1);
    match start(&config, &interfaces) {
        Ok(node) => {
            let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
            nodes().lock().unwrap().insert(handle, Arc::new(node));
            handle
        }
        Err(e) => {
            throw(&mut env, &e);
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_eu_neilalexander_yggdrasil_Yggdrasil_nativeStop(_: JNIEnv, _: JClass, handle: jlong) {
    let Some(node) = nodes().lock().unwrap().remove(&handle) else { return };
    node.stop.cancel();
    runtime().block_on(async {
        node.core.close_multicast().await;
        node.rwc.cleanup().await;
        let _ = node.core.close().await;
    });
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_eu_neilalexander_yggdrasil_Yggdrasil_nativeSend(
    env: JNIEnv,
    _: JClass,
    handle: jlong,
    buf: JByteArray,
    len: jint,
) {
    let mut packet = vec![0u8; len.max(0) as usize];
    // SAFETY: i8 and u8 have the same layout
    let target = unsafe { &mut *(packet.as_mut_slice() as *mut [u8] as *mut [i8]) };
    if env.get_byte_array_region(&buf, 0, target).is_err() {
        return;
    }
    let Some(node) = node(handle) else { return };
    let _ = runtime().block_on(node.rwc.write(&packet));
}

/// Blocks until a packet for the TUN arrives. Returns its length, or -1 once stopped.
#[unsafe(no_mangle)]
pub extern "system" fn Java_eu_neilalexander_yggdrasil_Yggdrasil_nativeRecv(
    env: JNIEnv,
    _: JClass,
    handle: jlong,
    buf: JByteArray,
) -> jint {
    let Some(node) = node(handle) else { return -1 };
    let capacity = env.get_array_length(&buf).unwrap_or(0).max(0) as usize;
    let mut packet = vec![0u8; capacity];
    let n = runtime().block_on(async {
        tokio::select! {
            _ = node.stop.cancelled() => None,
            r = node.rwc.read(&mut packet) => r.ok().map(|p| p.len()),
        }
    });
    let Some(n) = n else { return -1 };
    // SAFETY: i8 and u8 have the same layout
    let source = unsafe { &*(&packet[..n] as *const [u8] as *const [i8]) };
    if env.set_byte_array_region(&buf, 0, source).is_err() {
        return -1;
    }
    n as jint
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_eu_neilalexander_yggdrasil_Yggdrasil_nativeAddress(mut env: JNIEnv, _: JClass, handle: jlong) -> jstring {
    let Some(node) = node(handle) else { return std::ptr::null_mut() };
    let s = node.core.address().to_string();
    java_string(&mut env, &s)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_eu_neilalexander_yggdrasil_Yggdrasil_nativeSubnet(mut env: JNIEnv, _: JClass, handle: jlong) -> jstring {
    let Some(node) = node(handle) else { return std::ptr::null_mut() };
    let s = node.core.subnet().to_string();
    java_string(&mut env, &s)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_eu_neilalexander_yggdrasil_Yggdrasil_nativePublicKey(mut env: JNIEnv, _: JClass, handle: jlong) -> jstring {
    let Some(node) = node(handle) else { return std::ptr::null_mut() };
    let s = hex::encode(node.core.public_key());
    java_string(&mut env, &s)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_eu_neilalexander_yggdrasil_Yggdrasil_nativeMtu(_: JNIEnv, _: JClass, handle: jlong) -> jlong {
    node(handle).map_or(0, |n| n.rwc.mtu() as jlong)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_eu_neilalexander_yggdrasil_Yggdrasil_nativePeers(mut env: JNIEnv, _: JClass, handle: jlong) -> jstring {
    let Some(node) = node(handle) else { return std::ptr::null_mut() };
    let s = peers_json(&node);
    java_string(&mut env, &s)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_eu_neilalexander_yggdrasil_Yggdrasil_nativeTree(mut env: JNIEnv, _: JClass, handle: jlong) -> jstring {
    let Some(node) = node(handle) else { return std::ptr::null_mut() };
    let s = tree_json(&node);
    java_string(&mut env, &s)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_eu_neilalexander_yggdrasil_Yggdrasil_nativeRoutingEntries(_: JNIEnv, _: JClass, handle: jlong) -> jlong {
    let Some(node) = node(handle) else { return 0 };
    runtime().block_on(node.core.routing_entries()) as jlong
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_eu_neilalexander_yggdrasil_Yggdrasil_nativeRetryPeersNow(_: JNIEnv, _: JClass, handle: jlong) {
    let Some(node) = node(handle) else { return };
    runtime().block_on(node.core.retry_peers_now());
    node.core.force_router_refresh();
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_eu_neilalexander_yggdrasil_Yggdrasil_nativeUpdateNetworkInterfaces(
    mut env: JNIEnv,
    _: JClass,
    handle: jlong,
    interfaces: JString,
) {
    let Ok(text) = env.get_string(&interfaces) else { return };
    let text: String = text.into();
    if let Some(node) = node(handle) {
        node.core.update_network_interfaces(interfaces_from_json(&text));
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_eu_neilalexander_yggdrasil_Yggdrasil_nativeGenerateConfig(mut env: JNIEnv, _: JClass) -> jstring {
    let s = generate_config().to_string();
    java_string(&mut env, &s)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_eu_neilalexander_yggdrasil_Yggdrasil_nativeVersion(mut env: JNIEnv, _: JClass) -> jstring {
    java_string(&mut env, &format!("Yggdrasil-ng {NG_VERSION}"))
}
