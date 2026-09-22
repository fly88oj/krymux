//! Request routing: mapping stream targets to upstreams, with the same
//! semantics as the Node implementation.

use crate::mux::Target;

#[derive(Clone, Debug)]
/// Where a matched stream is forwarded to.
pub struct Upstream {
    pub host: Option<String>,
    pub port: u16,
    pub unix: Option<String>,
}

impl Upstream {
    /// Renders the upstream as a `host:port` or `unix:path` label.
    pub fn label(&self) -> String {
        if let Some(u) = &self.unix {
            format!("unix:{}", u)
        } else {
            format!(
                "{}:{}",
                self.host.as_deref().unwrap_or("127.0.0.1"),
                self.port
            )
        }
    }
}

#[derive(Clone, Debug)]
/// One route: match targets by host and port patterns, forward to an
/// upstream.
pub struct Route {
    pub hosts: Vec<String>,
    pub ports: Vec<PortPattern>,
    pub upstream: Option<Upstream>,
}

#[derive(Clone, Debug)]
/// Port matcher: exact value, inclusive range, or any.
pub enum PortPattern {
    Exact(u16),
    Range(u16, u16),
    Any,
}

#[derive(Clone, Debug, Default)]
/// Policy for dialing client-requested targets directly (no route needed).
pub struct ClientTargets {
    pub enabled: bool,
    pub allow_hosts: Vec<String>,
    pub allow_ports: Vec<PortPattern>,
}

/// Resolver built from compiled routes, a fallback upstream, and the
/// client-target policy.
pub struct Router {
    routes: Vec<Route>,
    fallback: Option<Upstream>,
    client_targets: ClientTargets,
}

/// Normalizes a host for matching: lowercased, brackets and a trailing
/// `:port` stripped, trailing dot removed. Returns `None` when nothing
/// remains.
pub fn normalize_host(h: &str) -> Option<String> {
    let mut s = h.trim().to_lowercase();
    if s.starts_with('[') {
        // [v6]
        let end = s.find(']')?;
        return Some(s[1..end].to_string());
    }
    if let Some(idx) = s.rfind(':') {
        // strip :port when it looks like host:port (no colons in a bare hostname)
        if !s[..idx].is_empty() && s.matches(':').count() == 1 {
            s = s[..idx].to_string();
        }
    }
    let s = s.trim_end_matches('.').to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Matches `host` against a pattern: exact, `*`, or `*.suffix` (one or more
/// labels under the suffix).
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let Some(p) = normalize_host(pattern) else {
        return false;
    };
    let Some(h) = normalize_host(host) else {
        return false;
    };
    if p == "*" || p == h {
        return true;
    }
    if let Some(suffix) = p.strip_prefix("*.") {
        let suf = format!(".{}", suffix);
        return h.ends_with(&suf) && !h[..h.len() - suf.len()].ends_with('.');
    }
    false
}

fn port_matches(patterns: &[PortPattern], port: u16) -> bool {
    patterns.is_empty()
        || patterns.iter().any(|p| match p {
            PortPattern::Any => true,
            PortPattern::Exact(p) => *p == port,
            PortPattern::Range(lo, hi) => port >= *lo && port <= *hi,
        })
}

impl Router {
    /// Builds a router from compiled routes, a fallback upstream, and the
    /// client-target policy.
    pub fn new(
        routes: Vec<Route>,
        fallback: Option<Upstream>,
        client_targets: ClientTargets,
    ) -> Self {
        Router {
            routes,
            fallback,
            client_targets,
        }
    }

    /// Resolves a stream target to a route, a direct dial, or a denial.
    pub fn resolve(&self, target: &Target) -> Decision {
        let host = target.host.as_deref().and_then(normalize_host);
        let port = target.port;
        for (i, r) in self.routes.iter().enumerate() {
            let host_ok = r.hosts.is_empty()
                || host
                    .as_deref()
                    .map(|h| r.hosts.iter().any(|p| host_matches(p, h)))
                    .unwrap_or(false);
            let port_ok = port_matches(&r.ports, port);
            if host_ok && port_ok {
                if let Some(up) = &r.upstream {
                    return Decision::Route {
                        order: i,
                        upstream: up.clone(),
                    };
                }
                if let Some(f) = &self.fallback {
                    return Decision::Route {
                        order: usize::MAX,
                        upstream: f.clone(),
                    };
                }
                return Decision::Deny {
                    reason: "route has no upstream".into(),
                };
            }
        }
        if let Some(f) = &self.fallback {
            return Decision::Route {
                order: usize::MAX,
                upstream: f.clone(),
            };
        }
        if self.client_targets.enabled {
            // unix-socket targets carry no host, so the allow_hosts check above
            // cannot govern them — dialing arbitrary server sockets (e.g.
            // /var/run/docker.sock) must be opt-in, never implied
            if target.unix.is_some() {
                return Decision::Deny {
                    reason: "client-chosen unix sockets are not allowed".into(),
                };
            }
            let host_ok = host
                .as_deref()
                .map(|h| {
                    self.client_targets
                        .allow_hosts
                        .iter()
                        .any(|p| host_matches(p, h))
                })
                .unwrap_or(true);
            let port_ok = port_matches(&self.client_targets.allow_ports, port);
            if host_ok && port_ok && port > 0 {
                return Decision::Dial;
            }
            return Decision::Deny {
                reason: "client target not allowed".into(),
            };
        }
        Decision::Deny {
            reason: "no route matched and client targets are disabled".into(),
        }
    }
}

/// The outcome of resolving a stream target.
pub enum Decision {
    /// Forward to a fixed upstream; `order` is the matching route's position.
    Route { order: usize, upstream: Upstream },
    /// Dial the client-requested target directly.
    Dial,
    /// Refuse the stream, with a reason for the log.
    Deny { reason: String },
}
