//! Host-level anomaly detection.
//!
//! This module performs heuristic-based behavioral analysis on a per-host basis.
//! It inspects accumulated connection metadata and emits structured alerts when
//! suspicious activity patterns are detected.
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
/// This function applies multiple independent heuristics against a single
/// host's behavioral profile. Each heuristic operates on pre-aggregated
/// state maintained inside [`HostProfile`].
///
/// Three independent checks are performed:
/// - **Port scan**: too many distinct destination ports within a short window.
/// - **SYN flood / DoS**: abnormally high SYN rate plus excessive half-open connections.
/// - **Lateral movement**: communication with many distinct internal hosts.
///
/// Each triggered condition results in:
/// 1. Emission of a structured log event via [`SharedLogger`].
/// 2. Incrementing the global alert counter in [`SharedStats`].
///
/// # Arguments
/// * `src`    - Source IP of the host being evaluated (used in alert metadata).
/// * `host`   - Mutable reference to the host's accumulated behavioral profile.
/// * `now`    - Current timestamp used for sliding-window eviction.
/// * `thresh` - Runtime detection thresholds (configurable at startup).
/// * `logger` - Shared structured logger instance.
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
    //
    // The host profile maintains a deque (`syn_times`) containing timestamps
    // of observed SYN packets. To ensure rate calculations remain bounded
    // to the configured observation window, we evict timestamps that fall
    // outside the `PORT_SCAN_WINDOW`.
    //
    // This guarantees:
    // - Memory usage does not grow unbounded.
    // - Rate calculations reflect only recent activity.
    while let Some(t) = host.syn_times.front() {
        // If the oldest SYN timestamp exceeds the allowed window,
        // remove it from the front of the deque.
        if now.duration_since(*t) > PORT_SCAN_WINDOW {
            host.syn_times.pop_front();
        } else {
            // Since timestamps are ordered, we can stop once we hit
            // a value still inside the observation window.
            break;
        }
    }

    // ── Port Scan Detection ──────────────────────────────────────────────────
    //
    // Detects reconnaissance behavior by checking how many distinct
    // destination ports the host has contacted.
    //
    // `host.ports` is expected to be a set of unique destination ports
    // observed within the tracking period.
    //
    // If the count exceeds the configured threshold, a PortScan event
    // is emitted.
    if host.ports.len() >= thresh.port_scan {
        logger.log(&Event::PortScan {
            src,
            port_count: host.ports.len(),
        });

        // Atomically increment the global alert counter.
        // `Relaxed` ordering is sufficient because we only require
        // eventual consistency for statistics aggregation.
        stats.alerts_emitted.fetch_add(1, Ordering::Relaxed);
    }

    // ── SYN Flood / DoS Detection ────────────────────────────────────────────
    //
    // Estimate SYN rate over the DoS observation window.
    //
    // SYN rate is calculated as:
    //     (# of SYN packets in window) / (window duration in seconds)
    //
    // This provides a packets-per-second metric.
    let syn_rate = host.syn_times.len() as f32 / DOS_WINDOW.as_secs_f32();

    // A DoS alert is triggered only if BOTH conditions hold:
    // 1. SYN rate exceeds the configured threshold.
    // 2. The number of half-open connections exceeds its threshold.
    //
    // Requiring both reduces false positives from benign high-traffic bursts.
    if syn_rate > thresh.dos_syn_rate && host.half_open > thresh.dos_half_open {
        logger.log(&Event::Dos {
            src,
            syn_rate,
            half_open: host.half_open,
        });

        // Increment global alert counter.
        stats.alerts_emitted.fetch_add(1, Ordering::Relaxed);
    }

    // ── Lateral Movement Detection ───────────────────────────────────────────
    //
    // Detects potential internal propagation by measuring the number
    // of distinct target hosts contacted.
    //
    // `host.targets` is expected to represent unique internal IPs
    // communicated with during the observation period.
    //
    // Excessive spread across internal hosts may indicate worm-like
    // behavior or post-compromise lateral movement.
    if host.targets.len() >= thresh.lateral {
        logger.log(&Event::LateralMovement {
            src,
            target_count: host.targets.len(),
        });

        // Increment global alert counter.
        stats.alerts_emitted.fetch_add(1, Ordering::Relaxed);
    }
}use crate::monitor::config::*;
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
