//! IP-range / port sweep — the [`TcpFs`](crate::TcpFs) banner grabber applied
//! across a host range and port list.
//!
//! [`expand_targets`] turns a host spec (a single IP, or an IPv4 CIDR like
//! `10.0.0.0/28`) and a port spec (`22,80,443`, ranges `8000-8010`, or the named
//! set `common`) into a flat list of `host:port` strings. `common` takes the
//! top `top-ports` entries from [`top_ports`]'s embedded ranking
//! (`top-ports.txt`) — how many is this plugin's `top-ports` setting
//! (published as [`PLUGIN_SCHEMA`], default 100; override with `exfil plugin
//! config scan`). Feeding the expanded list to [`TcpFs`](crate::TcpFs) and
//! [`scan_remote`](exfil_engine::scan_remote) means closed ports simply error
//! (and are counted as unreachable) while open ports have their banners
//! grabbed and scanned — a port scan with service banners, reusing the
//! existing pipeline.
//!
//! Active reconnaissance; only sweep ranges you are authorized to test. The
//! expansion is bounded to keep an accidental `/8` from generating millions of
//! targets.

use std::net::Ipv4Addr;
use std::sync::LazyLock;

use anyhow::{bail, Result};
use exfil_config::{FieldKind, FieldSchema, PluginSchema};

/// Hard cap on generated targets, so a wide CIDR can't blow up.
const MAX_TARGETS: usize = 65_536;

/// The common TCP ports, ranked most-common-first (see `top-ports.txt`).
static RANKED_PORTS: LazyLock<Vec<u16>> = LazyLock::new(|| {
    include_str!("../top-ports.txt")
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.trim().parse().ok())
        .collect()
});

/// This plugin's configurable settings, published for the `exfil plugin`
/// registry (see `exfil_config::PluginSchema`).
pub const PLUGIN_SCHEMA: PluginSchema = PluginSchema {
    name: "scan",
    fields: &[FieldSchema {
        key: "top-ports",
        description: "how many ports `--ports common` sweeps, ranked most-common-first",
        kind: FieldKind::Number { min: 1, max: 2000 },
        default: "100",
    }],
};

/// The top `n` most commonly open TCP ports, ranked most-common-first.
/// Clamped to the embedded ranking's length — asking for more than that just
/// returns the whole list.
pub fn top_ports(n: usize) -> Vec<u16> {
    RANKED_PORTS.iter().take(n).copied().collect()
}

/// Expand a host spec and a port spec into `host:port` targets. `top_n` is
/// the resolved `top-ports` setting, used when `ports` is `common`.
pub fn expand_targets(hosts: &str, ports: &str, top_n: usize) -> Result<Vec<String>> {
    let hosts = expand_hosts(hosts)?;
    let ports = expand_ports(ports, top_n)?;
    let total = hosts.len().saturating_mul(ports.len());
    if total > MAX_TARGETS {
        bail!("target set too large ({total} > {MAX_TARGETS}); narrow the range or ports");
    }
    let mut out = Vec::with_capacity(total);
    for h in &hosts {
        for p in &ports {
            out.push(format!("{h}:{p}"));
        }
    }
    Ok(out)
}

/// Expand a host spec: a single IP/host, or an IPv4 CIDR (`10.0.0.0/28`).
fn expand_hosts(spec: &str) -> Result<Vec<String>> {
    let spec = spec.trim();
    let Some((base, bits)) = spec.split_once('/') else {
        // Not a CIDR: a single host/IP passed through verbatim.
        return Ok(vec![spec.to_string()]);
    };
    let addr: Ipv4Addr = base
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid CIDR base address {base:?}"))?;
    let bits: u32 = bits
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid CIDR prefix /{bits}"))?;
    if bits > 32 {
        bail!("CIDR prefix /{bits} out of range");
    }
    let host_bits = 32 - bits;
    let count = 1u64 << host_bits;
    if count as usize > MAX_TARGETS {
        bail!("CIDR /{bits} covers {count} hosts; too broad");
    }
    let network = u32::from(addr) & (!0u32).checked_shl(host_bits).unwrap_or(0);
    Ok((0..count as u32)
        .map(|i| Ipv4Addr::from(network + i).to_string())
        .collect())
}

/// Expand a port spec: a comma list of ports and `a-b` ranges, or `common`
/// (the top `top_n` ranked ports).
fn expand_ports(spec: &str, top_n: usize) -> Result<Vec<u16>> {
    let spec = spec.trim();
    if spec.eq_ignore_ascii_case("common") {
        let ports = top_ports(top_n);
        if ports.is_empty() {
            // top_n == 0: same "nothing to sweep" case as an explicitly empty
            // spec below — bail instead of silently returning zero targets,
            // which would otherwise look identical to "swept it, found
            // nothing" rather than "misconfigured".
            bail!("top-ports is 0; nothing to sweep");
        }
        return Ok(ports);
    }
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once('-') {
            Some((a, b)) => {
                let (a, b): (u16, u16) = (
                    a.trim()
                        .parse()
                        .map_err(|_| anyhow::anyhow!("bad port {a:?}"))?,
                    b.trim()
                        .parse()
                        .map_err(|_| anyhow::anyhow!("bad port {b:?}"))?,
                );
                if a > b {
                    bail!("port range {a}-{b} is inverted");
                }
                ports.extend(a..=b);
            }
            None => ports.push(
                part.parse()
                    .map_err(|_| anyhow::anyhow!("bad port {part:?}"))?,
            ),
        }
    }
    if ports.is_empty() {
        bail!("no ports in spec {spec:?}");
    }
    Ok(ports)
}

/// Guess a service name and version from a grabbed banner, best-effort. Returns
/// `(service, version)` where either may be empty.
pub fn fingerprint(banner: &str) -> (String, String) {
    let first = banner
        .lines()
        .find(|l| !l.trim().is_empty() && !l.starts_with("target="))
        .unwrap_or("")
        .trim();
    // SSH: "SSH-2.0-OpenSSH_9.6p1".
    if let Some(rest) = first.strip_prefix("SSH-") {
        let version = rest.split(['-', ' ']).nth(1).unwrap_or("").to_string();
        return ("ssh".into(), version);
    }
    // HTTP: a "Server:" header anywhere in the banner.
    if let Some(server) = banner.lines().find_map(|l| {
        l.strip_prefix("Server:")
            .or_else(|| l.strip_prefix("server:"))
    }) {
        return ("http".into(), server.trim().to_string());
    }
    // SMTP/FTP greet with a numeric code then the product.
    if first.starts_with("220") {
        let svc = if first.to_ascii_lowercase().contains("ftp") {
            "ftp"
        } else {
            "smtp"
        };
        return (
            svc.into(),
            first.trim_start_matches("220").trim().to_string(),
        );
    }
    (String::new(), String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_single_host_and_port_list() {
        let t = expand_targets("10.0.0.5", "22,80,443", 100).unwrap();
        assert_eq!(t, ["10.0.0.5:22", "10.0.0.5:80", "10.0.0.5:443"]);
    }

    #[test]
    fn expands_cidr_and_port_range() {
        let t = expand_targets("192.168.1.0/30", "8000-8001", 100).unwrap();
        // /30 = 4 hosts × 2 ports = 8 targets.
        assert_eq!(t.len(), 8);
        assert!(t.contains(&"192.168.1.0:8000".to_string()));
        assert!(t.contains(&"192.168.1.3:8001".to_string()));
    }

    #[test]
    fn common_ports_expands_to_top_n() {
        let t = expand_targets("127.0.0.1", "common", 100).unwrap();
        assert_eq!(t.len(), 100);
        assert!(t.contains(&"127.0.0.1:80".to_string()), "{t:?}");

        // A smaller top_n yields fewer targets, still ranked-first.
        let t5 = expand_targets("127.0.0.1", "common", 5).unwrap();
        assert_eq!(t5.len(), 5);
    }

    #[test]
    fn top_ports_is_ranked_and_clamped() {
        let top = top_ports(3);
        assert_eq!(top.len(), 3);
        // A count past the embedded list's length just returns the whole list.
        let all = top_ports(usize::MAX);
        assert_eq!(all.len(), RANKED_PORTS.len());
    }

    #[test]
    fn common_with_zero_top_n_errors_instead_of_sweeping_nothing() {
        // top_n=0 must bail, not silently return zero targets — a caller
        // can't otherwise tell "misconfigured" from "swept it, found nothing".
        assert!(expand_targets("127.0.0.1", "common", 0).is_err());
    }

    #[test]
    fn rejects_broad_cidr_and_bad_specs() {
        assert!(expand_targets("10.0.0.0/8", "80", 100).is_err());
        assert!(expand_targets("10.0.0.0/33", "80", 100).is_err());
        assert!(expand_targets("nothost/24", "80", 100).is_err());
        assert!(expand_targets("1.2.3.4", "notaport", 100).is_err());
        assert!(expand_targets("1.2.3.4", "90-80", 100).is_err());
    }

    #[test]
    fn fingerprints_ssh_http_smtp() {
        assert_eq!(fingerprint("SSH-2.0-OpenSSH_9.6p1 Ubuntu").0, "ssh");
        assert_eq!(fingerprint("SSH-2.0-OpenSSH_9.6p1").1, "OpenSSH_9.6p1");
        let (svc, ver) = fingerprint("HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n");
        assert_eq!(svc, "http");
        assert_eq!(ver, "nginx/1.25.3");
        assert_eq!(fingerprint("220 mail.example.com ESMTP Postfix").0, "smtp");
    }

    #[test]
    fn total_size_and_empty_ports_are_rejected() {
        // Host count is at the cap but hosts × ports exceeds it → total bail.
        assert!(expand_targets("10.1.0.0/16", "80,443", 100).is_err());
        // A ports spec that yields no ports is rejected.
        assert!(expand_targets("127.0.0.1", "", 100).is_err());
    }

    #[test]
    fn fingerprint_ftp_and_unknown_banner() {
        assert_eq!(fingerprint("220 ProFTPD 1.3.7 Server").0, "ftp");
        assert_eq!(
            fingerprint("random noise\r\n"),
            (String::new(), String::new())
        );
    }
}
