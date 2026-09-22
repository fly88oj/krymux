//! JSON configuration loading — the same schema as the Node implementation
//! (camelCase keys).

use crate::router::{ClientTargets, PortPattern, Route, Upstream};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
/// Paths to this peer's PEM key/certificate pair.
pub struct IdentityCfg {
    pub key: String,
    pub cert: String,
}

#[derive(Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
/// Authorization settings: mode ("whitelist" or "open") plus the client
/// fingerprint whitelist.
pub struct AuthCfg {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub fingerprints: Vec<String>,
    #[serde(default)]
    pub clients: Vec<String>,
}
fn default_mode() -> String {
    "whitelist".into()
}

#[derive(Deserialize, Clone)]
/// One route rule as written in the config file, before compilation.
pub struct RawRoute {
    #[serde(default)]
    host: Option<serde_json::Value>,
    #[serde(default, rename = "hosts")]
    hosts_alt: Option<serde_json::Value>,
    #[serde(default)]
    port: Option<serde_json::Value>,
    #[serde(default, rename = "ports")]
    ports_alt: Option<serde_json::Value>,
    upstream: Option<serde_json::Value>,
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
/// The `clientTargets` block as written in the config file, before
/// compilation.
pub struct RawClientTargets {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    allow_hosts: Option<serde_json::Value>,
    #[serde(default)]
    allow_ports: Option<serde_json::Value>,
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
/// Server configuration, deserialized from JSON.
pub struct ServerCfg {
    pub listen: String,
    pub identity: IdentityCfg,
    #[serde(default)]
    pub auth: AuthCfg,
    #[serde(default)]
    pub routes: Vec<RawRoute>,
    #[serde(default)]
    pub fallback_upstream: Option<serde_json::Value>,
    #[serde(default, alias = "defaultUpstream")]
    pub fallback_upstream2: Option<serde_json::Value>,
    #[serde(default)]
    pub client_targets: Option<RawClientTargets>,
    #[serde(default = "default_keepalive")]
    pub keepalive_sec: u64,
    #[serde(default = "default_max_streams")]
    pub max_streams: usize,
    #[serde(default = "default_rx_window")]
    pub rx_window: u32,
    #[serde(default = "default_rx_window_max")]
    pub rx_window_max: u32,
    /// Optional raw zstd dictionary: when set (and this build has the `zstd`
    /// feature), the session additionally advertises `zstdd:<fp>` and
    /// upgrades `zstd`/`auto` negotiation when the peer registered the same
    /// dictionary. Absent (the default) keeps everything as before.
    #[serde(default)]
    pub zstd_dictionary: Option<PathBuf>,
    #[serde(default)]
    pub log: LogCfg,
}
fn default_keepalive() -> u64 {
    30
}
fn default_max_streams() -> usize {
    1024
}
fn default_rx_window() -> u32 {
    262_144
}
fn default_rx_window_max() -> u32 {
    4_194_304
}

#[derive(Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
/// Log settings.
pub struct LogCfg {
    #[serde(default = "default_level")]
    pub level: String,
}
fn default_level() -> String {
    "info".into()
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
/// Client configuration, deserialized from JSON.
pub struct ClientCfg {
    pub endpoint: String,
    pub identity: IdentityCfg,
    pub server_fingerprint: String,
    #[serde(default = "default_compression")]
    pub compression: String,
    #[serde(default = "default_keepalive")]
    pub keepalive_sec: u64,
    #[serde(default = "default_rx_window")]
    pub rx_window: u32,
    #[serde(default = "default_rx_window_max")]
    pub rx_window_max: u32,
    #[serde(default)]
    pub socks5: Option<String>,
    #[serde(default)]
    pub http_proxy: Option<String>,
    /// Optional raw zstd dictionary (see `ServerCfg::zstd_dictionary`).
    /// Registered here — at config load time — because the HELLO that
    /// advertises algorithms is built inside `EctunClient::connect`, which
    /// the CLI runs right after this load; `ConnectParams` has no dictionary
    /// field, so the process-global registry is the channel.
    #[serde(default)]
    pub zstd_dictionary: Option<PathBuf>,
    #[serde(default)]
    pub log: LogCfg,
}
fn default_compression() -> String {
    "auto".into()
}

fn value_strings(v: Option<serde_json::Value>) -> Vec<String> {
    match v {
        None => vec![],
        Some(serde_json::Value::String(s)) => vec![s],
        Some(serde_json::Value::Array(a)) => a
            .into_iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect(),
        _ => vec![],
    }
}

fn parse_ports(v: Option<serde_json::Value>) -> Vec<PortPattern> {
    let Some(v) = v else { return vec![] };
    let mut out = vec![];
    let items: Vec<serde_json::Value> = match v {
        serde_json::Value::Array(a) => a,
        other => vec![other],
    };
    for it in items {
        match it {
            serde_json::Value::Number(n) => {
                if let Some(p) = n.as_u64() {
                    out.push(PortPattern::Exact(p as u16));
                }
            }
            serde_json::Value::String(s) => {
                if s == "*" {
                    out.push(PortPattern::Any);
                } else if let Some((a, b)) = s.split_once('-') {
                    if let (Ok(a), Ok(b)) = (a.parse::<u16>(), b.parse::<u16>()) {
                        out.push(PortPattern::Range(a, b));
                    }
                } else if let Ok(p) = s.parse::<u16>() {
                    out.push(PortPattern::Exact(p));
                }
            }
            serde_json::Value::Array(pair) if pair.len() == 2 => {
                if let (Some(a), Some(b)) = (pair[0].as_u64(), pair[1].as_u64()) {
                    out.push(PortPattern::Range(a as u16, b as u16));
                }
            }
            _ => {}
        }
    }
    out
}

fn parse_upstream(v: Option<serde_json::Value>) -> Option<Upstream> {
    let v = v?;
    match v {
        serde_json::Value::String(s) => {
            if let Some(path) = s.strip_prefix("unix:") {
                return Some(Upstream {
                    host: None,
                    port: 0,
                    unix: Some(path.to_string()),
                });
            }
            let (host, port) = s.rsplit_once(':')?;
            Some(Upstream {
                host: Some(host.to_string()),
                port: port.parse().ok()?,
                unix: None,
            })
        }
        serde_json::Value::Array(a) if a.len() >= 2 => {
            let host = a[0].as_str()?.to_string();
            let port = a[1].as_u64()? as u16;
            Some(Upstream {
                host: Some(host),
                port,
                unix: None,
            })
        }
        serde_json::Value::Object(o) => {
            if let Some(u) = o.get("unix").and_then(|x| x.as_str()) {
                return Some(Upstream {
                    host: None,
                    port: 0,
                    unix: Some(u.to_string()),
                });
            }
            let host = o
                .get("host")
                .and_then(|x| x.as_str())
                .unwrap_or("127.0.0.1");
            let port = o.get("port").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
            Some(Upstream {
                host: Some(host.to_string()),
                port,
                unix: None,
            })
        }
        _ => None,
    }
}

/// Server configuration with fingerprints normalized and routes compiled
/// into their runtime form.
pub struct CompiledServer {
    pub cfg: ServerCfg,
    pub fingerprints: Vec<String>,
    pub routes: Vec<Route>,
    pub fallback: Option<Upstream>,
    pub client_targets: ClientTargets,
}

/// Loads, validates, and compiles a server config from a JSON file.
pub fn load_server_cfg(path: &Path) -> Result<CompiledServer> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
    let cfg: ServerCfg = serde_json::from_str(&text).context("parse server config")?;

    let mut fingerprints = vec![];
    for f in cfg.auth.fingerprints.iter().chain(cfg.auth.clients.iter()) {
        fingerprints.push(crate::keys::normalize_fingerprint(f)?);
    }

    let routes = cfg
        .routes
        .iter()
        .map(|r| Route {
            hosts: value_strings(r.host.clone().or_else(|| r.hosts_alt.clone())),
            ports: parse_ports(r.port.clone().or_else(|| r.ports_alt.clone())),
            upstream: parse_upstream(r.upstream.clone()),
        })
        .collect();

    let fallback = parse_upstream(
        cfg.fallback_upstream
            .clone()
            .or_else(|| cfg.fallback_upstream2.clone()),
    );

    let client_targets = match &cfg.client_targets {
        Some(ct) => ClientTargets {
            enabled: ct.enabled,
            allow_hosts: {
                let h = value_strings(ct.allow_hosts.clone());
                if h.is_empty() {
                    vec!["*".to_string()]
                } else {
                    h
                }
            },
            allow_ports: parse_ports(ct.allow_ports.clone()),
        },
        None => ClientTargets::default(),
    };

    Ok(CompiledServer {
        cfg,
        fingerprints,
        routes,
        fallback,
        client_targets,
    })
}

/// Loads a client config from a JSON file.
pub fn load_client_cfg(path: &Path) -> Result<ClientCfg> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
    let cfg: ClientCfg = serde_json::from_str(&text).context("parse client config")?;
    register_zstd_dictionary(&cfg.zstd_dictionary);
    Ok(cfg)
}

/// Registers a configured zstd dictionary with the compression layer.
/// All failure modes are reported and skipped — a bad dictionary path must
/// not stop the tunnel from coming up (streams simply negotiate without
/// `zstdd`, which is exactly the absent-field behavior).
pub(crate) fn register_zstd_dictionary(dict_path: &Option<PathBuf>) {
    let Some(path) = dict_path else { return };
    match std::fs::read(path) {
        Ok(bytes) => {
            let name = crate::compress::set_zstd_dictionary(&bytes);
            if name.is_empty() {
                eprintln!(
                    "krymux: zstdDictionary ignored (empty file or built without the zstd feature): {}",
                    path.display()
                );
            } else {
                eprintln!(
                    "krymux: zstd dictionary loaded from {} ({} bytes, advertises {})",
                    path.display(),
                    bytes.len(),
                    name
                );
            }
        }
        Err(e) => eprintln!("krymux: cannot read zstdDictionary {}: {e}", path.display()),
    }
}

/// Splits a listen string — `host:port`, `[v6]:port`, `:port`, or `port` —
/// into host and port.
pub fn parse_listen(s: &str) -> Result<(String, u16)> {
    // "host:port" or "[v6]:port" or ":port" or "port"
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']').context("bad listen")?;
        let host = rest[..end].to_string();
        let port: String = rest[end + 1..].trim_start_matches(':').to_string();
        return Ok((host, port.parse().context("bad port")?));
    }
    match s.rsplit_once(':') {
        Some((h, p)) => {
            let host = if h.is_empty() {
                "127.0.0.1".to_string()
            } else {
                h.to_string()
            };
            Ok((host, p.parse().context("bad port")?))
        }
        None => {
            if let Ok(p) = s.parse::<u16>() {
                Ok(("0.0.0.0".to_string(), p))
            } else {
                bail!("bad listen: {}", s)
            }
        }
    }
}
