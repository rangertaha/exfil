//! DNS resolution checks over extracted domains.
//!
//! This is an *online* enrichment (it queries the system resolver), kept out of
//! the default offline pipeline and driven instead by the `check-dns` command
//! over domains already stored in the graph. For each domain it resolves the
//! A/AAAA records and flags a domain that resolves to a **private, loopback, or
//! otherwise reserved** address — a signal of DNS rebinding, internal-service
//! exposure, or a sinkholed/parked domain.
//!
//! Resolution uses the standard library (`ToSocketAddrs`), so there is no async
//! runtime or extra dependency here; the caller runs it off the async thread.
//! WHOIS enrichment (registration age) is a planned companion that needs a
//! port-43 round-trip and is not implemented yet.

use std::net::{IpAddr, ToSocketAddrs};

use exfil_core::{Match, Severity};

/// Resolve a domain's IP addresses via the system resolver. Returns an empty
/// vec if it does not resolve (or on error).
pub fn resolve(domain: &str) -> Vec<IpAddr> {
    // ToSocketAddrs needs a port; any works for a name lookup.
    match (domain, 0u16).to_socket_addrs() {
        Ok(addrs) => addrs.map(|s| s.ip()).collect(),
        Err(_) => Vec::new(),
    }
}

/// Whether an address is private, loopback, link-local, or otherwise not a
/// normal public destination — the interesting case for a public domain.
pub fn is_reserved(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || v6.is_multicast(),
    }
}

/// Check one domain: if it resolves to any reserved address, return a finding.
/// `path` attributes the finding (e.g. the file the domain came from).
pub fn check_domain(domain: &str, path: &str) -> Option<Match> {
    let reserved: Vec<String> = resolve(domain)
        .into_iter()
        .filter(is_reserved)
        .map(|ip| ip.to_string())
        .collect();
    if reserved.is_empty() {
        return None;
    }
    Some(Match {
        rule: "dns-private-resolution".into(),
        path: path.to_string(),
        line: 0,
        col: 1,
        snippet: format!(
            "{domain} resolves to reserved address(es): {}",
            reserved.join(", ")
        ),
        severity: Some(Severity::Medium),
        cwe: Some("CWE-918".into()),
        cve: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn classifies_reserved_addresses() {
        assert!(is_reserved(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_reserved(&IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(is_reserved(&IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
        assert!(is_reserved(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        // A public address is not reserved.
        assert!(!is_reserved(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn localhost_resolves_to_loopback_and_flags() {
        // `localhost` is defined to resolve to a loopback address on any host.
        let ips = resolve("localhost");
        assert!(
            ips.iter().any(|ip| ip.is_loopback()),
            "localhost should resolve to loopback: {ips:?}"
        );
        let finding = check_domain("localhost", "f").expect("loopback is reserved");
        assert_eq!(finding.rule, "dns-private-resolution");
        assert!(finding.snippet.contains("reserved"), "{}", finding.snippet);
    }

    #[test]
    fn unresolvable_domain_yields_nothing() {
        // An invalid TLD does not resolve, so there is nothing to flag.
        assert!(check_domain("no-such-host.invalid", "f").is_none());
    }
}
