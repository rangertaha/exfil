//! IP-range / port sweep — the [`TcpFs`](crate::TcpFs) banner grabber applied
//! across a host range and port list.
//!
//! [`expand_targets`] turns a host spec (a single IP, or an IPv4 CIDR like
//! `10.0.0.0/28`) and a port spec (`22,80,443`, ranges `8000-8010`, or the named
//! set `common`) into a flat list of `host:port` strings. `common` takes the
//! first `top-ports` entries of [`COMMON_PORTS`] — how many is this plugin's
//! `top-ports` setting (published as [`PLUGIN_SCHEMA`], default 100; override
//! with `exfil plugin config scan`). Feeding the expanded list to [`TcpFs`](crate::TcpFs) and
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

/// TCP ports worth sweeping first, most interesting first.
///
/// These are IANA service assignments — facts, not authorship — ordered here by
/// what a security scan actually wants to see: the ways in (web, remote access,
/// file shares), then the things worth reaching once inside (databases,
/// directories, admin and monitoring surfaces), then the long tail.
///
/// Deliberately **not** a frequency ranking. An observed-frequency ordering is
/// somebody's measurement and carries their licence with it; this ordering is
/// our own editorial judgement about relevance, which is both licence-clean and
/// a better fit for a tool that grabs banners rather than counting open ports.
pub const COMMON_PORTS: &[u16] = &[
    // Web and web-adjacent — the most common way in, and the most likely to
    // hand back a revealing banner.
    80, 443, 8080, 8443, 8000, 8888, 8008, 8081, 8181, 8090, 3000, 5000, 9000, 4200, 4443, 7001,
    7080, 9090, 9443, 10000, 8085, 8086, 8161, 2375, 2376,
    // Remote access and management.
    22, 23, 3389, 5900, 5901, 5985, 5986, 512, 513, 514, 623, 992, 2222,
    // File transfer and sharing.
    21, 20, 445, 139, 137, 138, 2049, 111, 873, 989, 990, 115, 69, 548, 427, // Mail.
    25, 110, 143, 465, 587, 993, 995, 24, 209, 1109,
    // Databases and caches — high value, frequently exposed by accident.
    3306, 5432, 1433, 1521, 1830, 27017, 27018, 27019, 6379, 11211, 9042, 7000, 7199, 5984, 8529,
    9200, 9300, 2483, 2484, 50000, 3050, 5433, 26257, // Directory, auth and identity.
    389, 636, 88, 464, 749, 3268, 3269, 1812, 1813, 1645, 1646, 49, 750,
    // Name resolution and discovery.
    53, 5353, 5355, 1900, 3702, 17500, 5060, 5061, 4569,
    // Infrastructure, orchestration and monitoring.
    161, 162, 199, 2379, 2380, 6443, 10250, 10255, 4001, 7946, 8300, 8301, 8500, 8600, 2181, 9092,
    5672, 15672, 4369, 25672, 61616, 1883, 8883,
    // Version control, CI and artifact services.
    9418, 3690, 8929, 5050, 8153, 8081, 4873, 5001,
    // Printing, directory and legacy services.
    515, 631, 9100, 79, 113, 119, 563, 543, 544, 1080, 3128, 8118,
    // Remote procedure call and application servers.
    135, 593, 1099, 1098, 4444, 8009, 8880, 9001, 9002, 9080, 7777, 16992, 16993, 5555, 5560, 1494,
    2598, // Industrial and building control — rarely meant to be reachable.
    502, 20000, 44818, 47808, 1911, 4840, 102, 2404, 789, // Miscellaneous well-known.
    7, 9, 13, 17, 19, 37, 42, 70, 101, 105, 123, 177, 179, 220, 264, 322, 340, 416, 417, 444, 481,
    497, 500, 541, 555, 666, 700, 705, 711, 720, 726, 777, 800, 808, 843, 981, 1000, 1010, 1021,
    1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1110, 1234, 1352, 1687, 1701, 1717, 1723, 1755,
    1761, 1801, 1935, 2000, 2001, 2002, 2003, 2005, 2020, 2030, 2100, 2103, 2105, 2107, 2121, 2161,
    2190, 2196, 2200, 2251, 2260, 2288, 2301, 2323, 2366, 2382, 2393, 2394, 2399, 2401, 2492, 2500,
    2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809,
    2811, 2869, 2875, 2909, 2910, 2920, 2967, 2968, 2998, 3001, 3003, 3005, 3006, 3007, 3011, 3013,
    3017, 3031, 3052, 3071, 3077, 3211, 3221, 3260, 3261, 3280, 3283, 3300, 3301, 3323, 3324, 3325,
    3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3404, 3417, 3476, 3493, 3517, 3527, 3546, 3551,
    3580, 3659, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871,
    3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4002, 4003, 4004, 4005,
    4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279, 4321, 4343, 4445, 4446, 4449, 4550, 4567,
    4662, 4848, 4899, 4900, 4998, 5002, 5003, 5009, 5030, 5033, 5051, 5054, 5080, 5087, 5100, 5101,
    5102, 5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431,
    5432, 5440, 5500, 5510, 5544, 5550, 5566, 5631, 5633, 5678, 5679, 5718, 5730, 5800, 5801, 5802,
    5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5902, 5903, 5904, 5906, 5907, 5910, 5911,
    5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989, 5998, 5999, 6002,
    6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346,
    6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692,
    6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7002, 7004, 7007, 7019, 7025, 7070, 7100,
    7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741, 7778, 7800, 7911,
    7920, 7921, 7937, 7938, 7999, 8002, 8007, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8093, 8100,
    8192, 8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8333, 8400, 8402, 8500, 8600, 8649, 8651,
    8652, 8654, 8701, 8800, 8873, 8894, 8899, 8994, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9081,
    9099, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415, 9485, 9500, 9502, 9503, 9535,
    9575, 9593, 9594, 9595, 9618, 9666, 9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998,
    9999, 10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215,
    10243, 10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111, 11967, 12000,
    12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238, 14441, 14442, 15000, 15002,
    15003, 15004, 15660, 16000, 16001, 16016, 16018, 16080, 16113, 16851, 17877, 17988, 18040,
    18101, 18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842, 20005, 20031, 20221, 20222,
    20828, 21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355,
    27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772,
    32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785,
    33354, 33899, 34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176, 44442,
    44443, 45100, 48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161,
    49163, 49165, 49167, 49175, 49176, 49400, 49999, 50001, 50002, 50003, 50006, 50300, 50389,
    50500, 50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056,
    55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331,
    64623, 64680, 65000, 65129, 65389,
];

/// [`COMMON_PORTS`] with duplicates removed, order preserved.
///
/// The grouped literal above is organised for a human reader, so the same port
/// can legitimately appear under two headings (3389 is both remote access and
/// well-known; 8081 is both web and CI). Sweeping a host twice on one port is
/// wasted work and a duplicated finding, so dedupe once at startup.
static RANKED_PORTS: LazyLock<Vec<u16>> = LazyLock::new(|| {
    let mut seen = std::collections::HashSet::new();
    COMMON_PORTS
        .iter()
        .copied()
        .filter(|p| seen.insert(*p))
        .collect()
});

/// This plugin's configurable settings, published for the `exfil plugin`
/// registry (see `exfil_config::PluginSchema`).
pub const PLUGIN_SCHEMA: PluginSchema = PluginSchema {
    name: "scan",
    fields: &[FieldSchema {
        key: "top-ports",
        description: "how many ports `--ports common` sweeps, most interesting first",
        kind: FieldKind::Number { min: 1, max: 750 },
        default: "100",
    }],
};

/// The first `n` ports of [`COMMON_PORTS`], deduplicated.
/// Clamped to the list's length — asking for more than that just
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
    #[test]
    fn common_ports_are_deduplicated_and_plausible() {
        // The grouped literal repeats a few ports for readability; the swept
        // list must not, or a host gets probed twice on one port.
        let all = top_ports(usize::MAX);
        let mut sorted = all.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), all.len(), "RANKED_PORTS contains duplicates");

        // Enough entries to satisfy the schema's maximum, so the setting can
        // never promise more ports than exist.
        let max = match PLUGIN_SCHEMA.fields[0].kind {
            FieldKind::Number { max, .. } => max as usize,
            _ => unreachable!("top-ports is a number"),
        };
        assert!(
            all.len() >= max,
            "only {} ports for a max of {max}",
            all.len()
        );

        // Port 0 is not a target, and the obvious services must be present.
        assert!(!all.contains(&0));
        for p in [22u16, 80, 443, 445, 3389, 3306, 5432] {
            assert!(all.contains(&p), "missing well-known port {p}");
        }
        // The most interesting surfaces come first, not buried in the tail.
        let head = top_ports(24);
        assert!(head.contains(&80) && head.contains(&443));
    }
}
