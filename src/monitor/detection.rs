//! Host-level anomaly detection.
//!
//! This module implements detection of three classes of suspicious host behavior:
//! - **Port scanning**: rapid probing of many distinct destination ports
//! - **SYN flooding / DoS attacks**: high rate of SYN packets combined with many half-open connections
//! - **Lateral movement**: contact with many distinct internal hosts, indicating reconnaissance or propagation
//!
//! ## Key Design Decisions
//!
//! **Sliding windows**: Each detection heuristic maintains its own time window:
//! - Port scan detection uses a 30-second window (`PORT_SCAN_WINDOW`)
//! - DoS detection uses a 5-second window (`DOS_WINDOW`)
//! - Lateral movement uses an unbounded accumulator within a session
//!
//! **Alert deduplication**: To prevent alert storms when a threshold is crossed,
//! each alert type is throttled with a cooldown period (`ALERT_COOLDOWN`, default 30 s).
//! This ensures that even if a host continues malicious activity, alerts are emitted
//! at most once per cooldown interval, not on every packet.
//!
//! **Window resets**: When an alert fires, its associated accumulator is cleared
//! to detect fresh bursts of activity rather than re-alerting on stale data.
//!
//! ## Bugs Fixed in This Version
//!
//! ### Bug 2a — `ports` HashSet never cleared
//! **Problem**: The `ports` set grew without bounds. A host that port-scanned
//! 15 targets once would trigger a port-scan alert on every subsequent packet
//! indefinitely, despite the attacking behavior having ceased.
//! **Fix**: After firing a port-scan alert, both `ports` and `syn_times` are
//! cleared so the detector resets and waits for a fresh burst.
//!
//! ### Bug 2b — `targets` HashSet never cleared
//! **Problem**: Same issue for lateral-movement detection; accumulated targets
//! were never cleared, causing indefinite re-alerting.
//! **Fix**: The `targets` set is cleared after a lateral-movement alert fires.
//!
//! ### Bug 2c — DoS rate computed over wrong window
//! **Problem**: `syn_times` was bounded to `PORT_SCAN_WINDOW` (30 s) but the
//! DoS rate denominator used `DOS_WINDOW` (5 s), inflating the computed rate ~6×.
//! This caused false-positive DoS detections.
//! **Fix**: `HostProfile` now carries a separate `dos_syn_times` deque bounded
//! to `DOS_WINDOW`. DoS rate is computed from that deque; port-scan window
//! maintenance continues to use `syn_times`.
//!
//! ### Bug 3 — Alert storm on every packet
//! **Problem**: Once a threshold was crossed, an alert fired on every subsequent
//! packet with no deduplication, flooding logs and inflating `alerts_emitted`.
//! **Fix**: Each alert type has a per-host `last_alert_*: Option<Instant>` field.
//! An alert is suppressed if the same type fired within `ALERT_COOLDOWN`.

use crate::logger::{Event, SharedLogger};
use crate::monitor::config::*;
use crate::monitor::types::{ALERT_COOLDOWN, HostProfile, SharedStats, Thresholds};
use std::sync::atomic::Ordering;
use std::time::Instant;

/// Analyses a host's accumulated behavioural data and flags suspicious patterns.
///
/// Three independent heuristic checks are performed:
/// - **Port scan**: too many distinct destination ports within `PORT_SCAN_WINDOW`.
/// - **SYN flood / DoS**: high SYN rate (over `DOS_WINDOW`) + many half-open conns.
/// - **Lateral movement**: contact with too many distinct internal hosts.
///
/// Each check fires at most once per `ALERT_COOLDOWN` per host (30 s by
/// default) to prevent alert storms once a threshold has been crossed.
pub fn detect_host_anomalies(
    src:    &str,
    host:   &mut HostProfile,
    now:    Instant,
    thresh: &Thresholds,
    logger: &SharedLogger,
    stats:  &SharedStats,
) {
    // ── Sliding Window Maintenance ───────────────────────────────────────────
    // Remove stale entries from both time windows to ensure accurate rate
    // calculations and prevent memory bloat from long-lived connections.

    // Evict port-scan SYN timestamps older than PORT_SCAN_WINDOW (30 s).
    while let Some(t) = host.syn_times.front() {
        if now.duration_since(*t) > PORT_SCAN_WINDOW {
            host.syn_times.pop_front();
        } else {
            break;
        }
    }

    // Evict DoS SYN timestamps older than DOS_WINDOW (5 s).
    // This is a separate deque so the DoS rate denominator is correct.
    // FIX 2c: Prevents inflation of DoS rate calculations.
    while let Some(t) = host.dos_syn_times.front() {
        if now.duration_since(*t) > DOS_WINDOW {
            host.dos_syn_times.pop_front();
        } else {
            break;
        }
    }

    // If the port-scan window is now empty, clear the ports set so it does not
    // carry stale entries into future windows.
    // FIX 2a: Prevents indefinite re-alerting on stale port-scan data.
    if host.syn_times.is_empty() {
        host.ports.clear();
    }

    // ── Port Scan Detection ──────────────────────────────────────────────────
    // Triggers when a host contacts too many distinct destination ports in
    // rapid succession, indicating systematic network reconnaissance.
    if host.ports.len() >= thresh.port_scan {
        // FIX 3: Check cooldown to suppress alert storms on every packet.
        let should_alert = host.last_alert_port_scan
            .map_or(true, |t| now.duration_since(t) >= ALERT_COOLDOWN);

        if should_alert {
            logger.log(&Event::PortScan {
                src,
                port_count: host.ports.len(),
            });
            stats.alerts_emitted.fetch_add(1, Ordering::Relaxed);
            host.last_alert_port_scan = Some(now);

            // Reset the port set and SYN window so the detector looks for a
            // fresh burst rather than re-triggering on the same stale data.
            // FIX 2a: Clear accumulators after alert to detect new activity.
            host.ports.clear();
            host.syn_times.clear();
        }
    }

    // ── SYN Flood / DoS Detection ────────────────────────────────────────────
    // Triggers when both conditions hold:
    // 1. High rate of SYN packets (over DOS_WINDOW, typically 5 seconds)
    // 2. Many half-open connections (incomplete TCP handshakes)
    // This dual-condition check filters out legitimate high-traffic scenarios.
    //
    // Rate is computed over DOS_WINDOW (5 s) using the dedicated dos_syn_times
    // deque, which is evicted to that window above. Previously syn_times (30 s)
    // was used here, inflating the computed rate by up to 6×.
    // FIX 2c: Separate deque ensures correct rate denominator.
    let syn_rate = host.dos_syn_times.len() as f32 / DOS_WINDOW.as_secs_f32();
    if syn_rate > thresh.dos_syn_rate && host.half_open > thresh.dos_half_open {
        // FIX 3: Check cooldown to suppress alert storms on every packet.
        let should_alert = host.last_alert_dos
            .map_or(true, |t| now.duration_since(t) >= ALERT_COOLDOWN);

        if should_alert {
            logger.log(&Event::Dos {
                src,
                syn_rate,
                half_open: host.half_open,
            });
            stats.alerts_emitted.fetch_add(1, Ordering::Relaxed);
            host.last_alert_dos = Some(now);
        }
    }

    // ── Lateral Movement Detection ───────────────────────────────────────────
    // Triggers when a host establishes connections to many distinct internal
    // targets, suggesting either active reconnaissance (moving through the
    // network) or automated worm propagation.
    if host.targets.len() >= thresh.lateral {
        // FIX 3: Check cooldown to suppress alert storms on every packet.
        let should_alert = host.last_alert_lateral
            .map_or(true, |t| now.duration_since(t) >= ALERT_COOLDOWN);

        if should_alert {
            logger.log(&Event::LateralMovement {
                src,
                target_count: host.targets.len(),
            });
            stats.alerts_emitted.fetch_add(1, Ordering::Relaxed);
            host.last_alert_lateral = Some(now);

            // Clear targets so the detector watches for a fresh wave rather
            // than re-alerting on the same accumulated set every packet.
            // FIX 2b: Clear accumulators after alert to detect new activity.
            host.targets.clear();
        }
    }
}