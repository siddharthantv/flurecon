//! Host-level anomaly detection.
//!
//! Changes from v0.1.0:
//! - Hard-coded thresholds replaced with the [`Thresholds`] struct populated
//!   from CLI arguments, so no recompile is needed to tune sensitivity.
//! - `println!` replaced with structured [`Logger`] events.
//! - [`SharedStats`] alert counter is incremented for every alert fired.

use crate::logger::{Event, SharedLogger};
use crate::monitor::config::*;
use crate::monitor::types::{HostProfile, SharedStats, Thresholds};
use std::sync::atomic::Ordering;
use std::time::Instant;

/// Analyses a host's accumulated connection data and flags suspicious patterns.
///
/// Three independent heuristic checks are performed:
/// - **Port scan**: too many distinct destination ports in the sliding window.
/// - **SYN flood / DoS**: high SYN rate combined with many half-open connections.
/// - **Lateral movement**: contact with a large number of distinct internal hosts.
///
/// # Arguments
/// * `src`    - Source IP of the host being evaluated (for log output).
/// * `host`   - Mutable reference to the host's accumulated profile.
/// * `now`    - Current timestamp, used to evict stale SYN window entries.
/// * `thresh` - Runtime detection thresholds from CLI args or defaults.
/// * `logger` - Shared structured logger.
/// * `stats`  - Shared session statistics; alert counter is incremented here.
pub fn detect_host_anomalies(
    src:    &str,
    host:   &mut HostProfile,
    now:    Instant,
    thresh: &Thresholds,
    logger: &SharedLogger,
    stats:  &SharedStats,
) {
    // ── Sliding Window Maintenance ───────────────────────────────────────────
    // Evict SYN timestamps outside the port-scan observation window.
    while let Some(t) = host.syn_times.front() {
        if now.duration_since(*t) > PORT_SCAN_WINDOW {
            host.syn_times.pop_front();
        } else {
            break;
        }
    }

    // ── Port Scan Detection ──────────────────────────────────────────────────
    if host.ports.len() >= thresh.port_scan {
        logger.log(&Event::PortScan {
            src,
            port_count: host.ports.len(),
        });
        stats.alerts_emitted.fetch_add(1, Ordering::Relaxed);
    }

    // ── SYN Flood / DoS Detection ────────────────────────────────────────────
    let syn_rate = host.syn_times.len() as f32 / DOS_WINDOW.as_secs_f32();
    if syn_rate > thresh.dos_syn_rate && host.half_open > thresh.dos_half_open {
        logger.log(&Event::Dos {
            src,
            syn_rate,
            half_open: host.half_open,
        });
        stats.alerts_emitted.fetch_add(1, Ordering::Relaxed);
    }

    // ── Lateral Movement Detection ───────────────────────────────────────────
    if host.targets.len() >= thresh.lateral {
        logger.log(&Event::LateralMovement {
            src,
            target_count: host.targets.len(),
        });
        stats.alerts_emitted.fetch_add(1, Ordering::Relaxed);
    }
}
