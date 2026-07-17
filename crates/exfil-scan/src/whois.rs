//! WHOIS enrichment: flag newly-registered domains (a common phishing signal).
//!
//! Like the [`dns`](crate::dns) checker, this is an *online* enrichment driven
//! by a command over domains already in the graph, not part of the offline
//! pipeline. For each domain it does a port-43 WHOIS lookup (via the IANA
//! referral for the TLD), parses the registration date, and flags a domain
//! registered within a recency threshold.
//!
//! No date-library dependency: dates are parsed as `YYYY-MM-DD` and converted to
//! days-since-epoch with a civil-date algorithm, then compared to today.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use exfil_core::{Match, Severity};

/// Connect timeout / read timeout for a WHOIS query.
const TIMEOUT: Duration = Duration::from_secs(5);
/// Default "newly registered" threshold in days.
pub const DEFAULT_RECENT_DAYS: i64 = 30;

/// Query a WHOIS server (port 43) for `domain`, returning the raw response.
pub fn query(server: &str, domain: &str) -> anyhow::Result<String> {
    let addr = (server, 43u16)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no address for whois server {server}"))?;
    query_addr(addr, domain)
}

/// Send a WHOIS request to an already-resolved address and read the response.
/// Split out from [`query`] so the request/read path is testable against a
/// local listener without depending on port 43 or DNS.
fn query_addr(addr: std::net::SocketAddr, domain: &str) -> anyhow::Result<String> {
    let mut stream = TcpStream::connect_timeout(&addr, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    stream.write_all(format!("{domain}\r\n").as_bytes())?;
    let mut out = String::new();
    stream.read_to_string(&mut out)?;
    Ok(out)
}

/// The WHOIS server for a domain's TLD, from the IANA referral. Falls back to
/// `whois.iana.org` itself if no referral is found.
pub fn referral_server(iana_response: &str) -> Option<String> {
    field(iana_response, "whois:")
}

/// Do the two-step lookup (IANA referral → authoritative server) for `domain`.
pub fn lookup(domain: &str) -> anyhow::Result<String> {
    let tld = domain.rsplit('.').next().unwrap_or(domain);
    let iana = query("whois.iana.org", tld)?;
    match referral_server(&iana) {
        Some(server) => query(&server, domain),
        None => Ok(iana),
    }
}

/// Extract the value of the first line beginning with `key` (case-insensitive),
/// trimmed.
fn field(text: &str, key: &str) -> Option<String> {
    let key_l = key.to_ascii_lowercase();
    text.lines().find_map(|l| {
        let l = l.trim();
        l.to_ascii_lowercase()
            .strip_prefix(&key_l)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    })
}

/// Parse a registration date from a WHOIS response as days since the Unix epoch.
/// Recognizes the common `Creation Date`/`Created`/`Registered on` fields and a
/// leading `YYYY-MM-DD`.
pub fn creation_epoch_days(whois: &str) -> Option<i64> {
    const KEYS: &[&str] = &[
        "creation date:",
        "created:",
        "created on:",
        "registered on:",
        "registration time:",
        "domain registration date:",
    ];
    let value = KEYS.iter().find_map(|k| field(whois, k))?;
    parse_ymd(&value)
}

/// Parse a leading `YYYY-MM-DD` into days since the Unix epoch.
fn parse_ymd(s: &str) -> Option<i64> {
    let date = s.get(..10)?; // YYYY-MM-DD
    let mut parts = date.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: i64 = parts.next()?.parse().ok()?;
    let d: i64 = parts.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(days_from_civil(y, m, d))
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Today as days since the Unix epoch (UTC).
pub fn today_epoch_days() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86_400) as i64)
        .unwrap_or(0)
}

/// If `domain`'s WHOIS shows a registration within `recent_days` of `today`,
/// return a finding. `path` attributes it.
pub fn check(whois: &str, domain: &str, today: i64, recent_days: i64, path: &str) -> Option<Match> {
    let created = creation_epoch_days(whois)?;
    let age = today - created;
    if age < 0 || age > recent_days {
        return None;
    }
    Some(Match {
        rule: "whois-newly-registered".into(),
        path: path.to_string(),
        line: 0,
        col: 1,
        snippet: format!("{domain} registered {age} day(s) ago"),
        severity: Some(Severity::Medium),
        cwe: Some("CWE-1007".into()),
        cve: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn parses_creation_date_fields() {
        let whois = "Domain Name: EXAMPLE.COM\r\nCreation Date: 2024-03-15T10:00:00Z\r\n";
        let days = creation_epoch_days(whois).unwrap();
        assert_eq!(days, days_from_civil(2024, 3, 15));
        // Alternative field spelling.
        assert!(creation_epoch_days("Registered on: 2020-01-01").is_some());
        // No date → None.
        assert!(creation_epoch_days("Domain Name: X\r\n").is_none());
    }

    #[test]
    fn civil_date_matches_known_epochs() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 1, 1), 10957);
    }

    #[test]
    fn referral_extraction() {
        let iana = "domain: COM\r\nwhois: whois.verisign-grs.com\r\n";
        assert_eq!(
            referral_server(iana).as_deref(),
            Some("whois.verisign-grs.com")
        );
    }

    #[test]
    fn flags_recent_registration_only() {
        let today = days_from_civil(2024, 6, 1);
        let recent = "Creation Date: 2024-05-20\r\n"; // ~12 days old
        assert!(check(recent, "new.test", today, DEFAULT_RECENT_DAYS, "f").is_some());
        let old = "Creation Date: 2010-01-01\r\n";
        assert!(check(old, "old.test", today, DEFAULT_RECENT_DAYS, "f").is_none());
    }

    #[test]
    fn query_addr_talks_to_a_whois_server() {
        // A localhost "WHOIS" server that echoes a canned record.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 128];
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(b"Domain Name: T\r\nCreation Date: 2021-01-01\r\n");
            }
        });
        let out = query_addr(addr, "t.test").unwrap();
        assert!(creation_epoch_days(&out).is_some(), "{out}");
        server.join().unwrap();
    }

    #[test]
    fn query_errors_on_unresolvable_host() {
        assert!(query("no-such-host.invalid", "x.test").is_err());
    }

    #[test]
    fn parse_ymd_rejects_out_of_range_month_and_day() {
        assert!(parse_ymd("2024-13-01").is_none()); // month 13
        assert!(parse_ymd("2024-02-40").is_none()); // day 40
        assert!(parse_ymd("not-a-date").is_none()); // non-numeric
        assert!(parse_ymd("2024-06-15").is_some());
    }

    #[test]
    fn today_epoch_days_is_plausible() {
        // Days since 1970 for any run after 2021-01-01 (18628) and before 2100.
        let today = today_epoch_days();
        assert!((18628..47482).contains(&today), "{today}");
    }
}
