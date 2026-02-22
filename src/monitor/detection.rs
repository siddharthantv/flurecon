use crate::monitor::config::*;
use crate::monitor::types::HostProfile;
use std::time::Instant;

/// Analyses a host's accumulated connection data and flags suspicious behaviour patterns.
///
/// This function is intended to be called once per packet (or on a periodic tick) for each
/// active host. It performs three independent heuristic checks:
///
/// - **Port scan detection**: if the host has probed an unusually large number of distinct
///   destination ports within the [`PORT_SCAN_WINDOW`], it is likely performing reconnaissance.
/// - **SYN flood / DoS detection**: a high rate of SYN packets combined with a large number
///   of half-open connections suggests a denial-of-service attempt or a fast-scanning tool.
/// - **Lateral movement detection**: contact with a large number of distinct internal targets
///   may indicate an attacker moving through the network after an initial compromise.
///
/// # Arguments
/// * `src`  - Source IP address of the host being evaluated, used only for log output.
/// * `host` - Mutable reference to the [`HostProfile`] holding the host's connection history.
/// * `now`  - Current timestamp, used to expire stale entries from the SYN sliding window.
pub fn detect_host_anomalies(src: &str, host: &mut HostProfile, now: Instant) {
    // ── Sliding Window Maintenance ───────────────────────────────────────────────

    // Evict SYN timestamps that fall outside the port-scan observation window.
    // The deque is maintained in insertion order, so we only need to drain from the front
    // until we find an entry that is still within the window.
    while let Some(t) = host.syn_times.front() {
        if now.duration_since(*t) > PORT_SCAN_WINDOW {
            host.syn_times.pop_front();
        } else {
            break;
        }
    }

    // ── Port Scan Detection ──────────────────────────────────────────────────────

    // A host that has connected to 15 or more distinct destination ports within the
    // observation window is flagged as a likely port scanner. Legitimate hosts rarely
    // contact this many ports in a short period.
    if host.ports.len() >= 15 {
        println!("[PORT SCAN] {} scanned {} ports", src, host.ports.len());
    }

    // ── SYN Flood / DoS Detection ────────────────────────────────────────────────

    // Compute the SYN rate over the DoS observation window. A high SYN rate alone can
    // be benign (e.g., a busy web client), so we require both an elevated rate *and* a
    // large number of half-open connections before alerting. Half-open connections that
    // are never completed with a final ACK are the hallmark of a SYN flood attack.
    let syn_rate = host.syn_times.len() as f32 / DOS_WINDOW.as_secs_f32();
    if syn_rate > 20.0 && host.half_open > 10 {
        println!(
            "[DoS] {} SYN rate {:.1}/s half-open {}",
            src, syn_rate, host.half_open
        );
    }

    // ── Lateral Movement Detection ───────────────────────────────────────────────

    // A host communicating with 10 or more distinct internal targets is a potential
    // indicator of lateral movement — an attacker pivoting across the network from a
    // beachhead host. Combined with other signals (e.g., unusual ports or protocols),
    // this can help identify post-compromise reconnaissance.
    if host.targets.len() >= 10 {
        println!(
            "[LATERAL MOVEMENT] {} contacted {} internal hosts",
            src,
            host.targets.len()
        );
    }
}