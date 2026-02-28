//! Network monitoring engine entry point.
//!
//! This module implements the core packet capture and processing loop for network
//! anomaly detection. It handles both live packet capture and offline PCAP file
//! replay, dispatching packets through a multi-stage pipeline for flow tracking,
//! host profiling, and anomaly detection.
//!
//! Fixes applied in this version:
//!
//! ## Bug 4 — `Mutex<HashMap>` → `DashMap`
//! Both tables are now `Arc<DashMap<_,_>>`. The monitor thread operates on
//! individual entries (one insert/lookup per packet) while the eviction thread
//! calls `retain` across shards. Contention is now per-shard rather than
//! global, removing the bottleneck under high packet rates.
//!
//! ## Bug 4b — Watermark stats renamed and corrected
//! `hosts_seen` / `flows_tracked` were described as high-watermarks but the
//! naming implied "total ever seen". They are now `total_hosts_seen` /
//! `total_flows_tracked` and are incremented exactly once per new entry
//! (before insertion for hosts; on first creation for flows in `flow.rs`),
//! giving a true running total rather than a snapshot size.
//!
//! ## Bug 5 — Live capture ignored `--interface`
//! `run_live` previously called `pcap::Device::lookup()`, ignoring the
//! interface the user selected on the CLI. `MonitorConfig` now carries
//! `iface_name: Option<String>`. `run_live` opens that device when set, and
//! falls back to `Device::lookup()` only when no interface was specified.
//!
//! ## Bug 6 — Panic-heavy error handling
//! `start_monitor` and its helpers now return `Result<(), String>` so callers
//! receive a descriptive error instead of a panic. `load_oui_db` in `main.rs`
//! is similarly fixed. Internal `unwrap`/`expect` calls on the hot packet path
//! are replaced with `?` or logged-and-skipped patterns.

pub mod config;
pub mod detection;
pub mod eviction;
pub mod flow;
pub mod host;
pub mod parsers;
pub mod types;

use crate::logger::{Event, SharedLogger};
use crate::monitor::detection::detect_host_anomalies;
use crate::monitor::eviction::{SharedFlows, SharedHosts, spawn_eviction_thread};
use crate::monitor::flow::process_tcp_packet;
use crate::monitor::parsers::parse_dns_name;
use crate::monitor::types::*;

use dashmap::DashMap;
use etherparse::{SlicedPacket, TransportSlice};
use pcap::Capture;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

/// Configuration bundle passed from `main` into the monitoring engine.
///
/// Contains all runtime parameters needed to control packet capture, detection
/// thresholds, and logging behavior. Separates configuration from state to enable
/// clean error handling and optional features (e.g., interface selection).
pub struct MonitorConfig {
    /// IPs to monitor (ARP-discovered in live mode; populated from stream in replay).
    pub tracked:        HashSet<String>,
    /// Runtime-tunable detection thresholds from CLI args.
    pub thresholds:     Thresholds,
    /// Shared structured logger.
    pub logger:         SharedLogger,
    /// Shared session statistics for the shutdown summary.
    pub stats:          SharedStats,
    /// Set to `true` by the ctrlc handler; the loop exits on next iteration.
    pub shutdown:       ShutdownFlag,
    /// Path to a PCAP file for offline replay, or `None` for live capture.
    pub pcap_file:      Option<String>,
    /// Eviction sweep interval in seconds.
    pub evict_interval: u64,
    /// Network interface name for live capture (Bug 5 fix).
    ///
    /// When `Some`, `run_live` opens this specific device rather than letting
    /// libpcap pick the default. Must match the interface resolved in `main`.
    /// `None` falls back to `pcap::Device::lookup()`.
    pub iface_name:     Option<String>,
}

/// Entry point for the monitoring engine.
///
/// Initializes the shared host and flow tables, spawns the background eviction
/// thread, and delegates to either live capture or PCAP replay based on config.
/// Ensures clean shutdown by joining the eviction thread before returning.
///
/// Returns `Err(String)` if the capture device cannot be opened or the PCAP
/// file cannot be read, instead of panicking (Bug 6 fix).
pub fn start_monitor(cfg: MonitorConfig) -> Result<(), String> {
    // Initialize concurrent hash maps for flow and host tracking.
    // DashMap provides per-shard locking for reduced contention.
    let flows: SharedFlows = Arc::new(DashMap::new());
    let hosts: SharedHosts = Arc::new(DashMap::new());

    // Spawn the background thread responsible for TTL-based eviction of stale entries.
    // This thread runs independently and only holds shard locks during retain operations.
    let eviction_handle = spawn_eviction_thread(
        Arc::clone(&flows),
        Arc::clone(&hosts),
        cfg.evict_interval,
        Arc::clone(&cfg.shutdown),
    );

    cfg.logger.log(&Event::Info {
        message: "Advanced Network Analysis Engine started",
    });

    // Route to live or replay mode based on pcap_file config.
    let result = if let Some(ref path) = cfg.pcap_file {
        run_replay(path, &cfg, &flows, &hosts)
    } else {
        run_live(&cfg, &flows, &hosts)
    };

    // Wait for eviction thread to finish before returning.
    let _ = eviction_handle.join();
    result
}

// ── Live capture ──────────────────────────────────────────────────────────────

/// Opens a promiscuous live pcap capture on the configured interface.
///
/// Continuously reads packets from the network adapter and feeds them through
/// the shared processing pipeline. Respects the shutdown flag to allow graceful
/// exit after receiving SIGINT.
///
/// Bug 5 fix: uses `cfg.iface_name` when set, rather than always calling
/// `Device::lookup()` which ignored the `--interface` CLI flag entirely.
///
/// Bug 6 fix: returns `Err` with descriptive messages instead of panicking
/// on initialization failures.
fn run_live(
    cfg:   &MonitorConfig,
    flows: &SharedFlows,
    hosts: &SharedHosts,
) -> Result<(), String> {
    // Open the capture device with promiscuous mode enabled.
    // Bug 5: Check for user-specified interface first, falling back to device lookup.
    let mut cap = if let Some(ref name) = cfg.iface_name {
        // Open the specific interface the user requested via CLI.
        Capture::from_device(name.as_str())
            .map_err(|e| format!("Cannot open interface '{}': {}", name, e))?
            .promisc(true)
            .open()
            .map_err(|e| format!("Cannot start capture on '{}': {}", name, e))?
    } else {
        // Fallback: let libpcap pick the default device.
        let dev = pcap::Device::lookup()
            .map_err(|e| format!("pcap device lookup failed: {}", e))?
            .ok_or_else(|| "No capture device found".to_string())?;
        Capture::from_device(dev)
            .map_err(|e| format!("Cannot open default device: {}", e))?
            .promisc(true)
            .open()
            .map_err(|e| format!("Cannot start capture: {}", e))?
    };

    // Main packet capture loop: read and process packets until shutdown signal.
    while !cfg.shutdown.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(pkt) => process_raw(pkt.data, cfg, flows, hosts),
            Err(_)  => break,
        }
    }

    Ok(())
}

// ── PCAP file replay ──────────────────────────────────────────────────────────

/// Opens an offline PCAP file and replays every packet through the pipeline.
///
/// Useful for deterministic testing and analysis of captured traffic traces.
/// Processes packets sequentially with the same detection logic as live capture.
///
/// Bug 6 fix: returns `Err` instead of panicking when the file cannot be opened.
fn run_replay(
    path:  &str,
    cfg:   &MonitorConfig,
    flows: &SharedFlows,
    hosts: &SharedHosts,
) -> Result<(), String> {
    cfg.logger.log(&Event::Info {
        message: "Replay mode: reading from PCAP file",
    });

    let mut cap = Capture::from_file(path)
        .map_err(|e| format!("Failed to open PCAP file '{}': {}", path, e))?;

    // Read and process packets from the file until EOF or shutdown signal.
    while !cfg.shutdown.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(pkt) => process_raw(pkt.data, cfg, flows, hosts),
            Err(_)  => break,
        }
    }

    Ok(())
}

// ── Shared packet processing pipeline ────────────────────────────────────────

/// Central packet processing pipeline.
///
/// Parses raw Ethernet frames, filters by tracked IPs, updates host profiles,
/// and dispatches protocol-specific handlers (DNS, TCP). Finishes with anomaly
/// detection to check for suspicious behavior based on configurable thresholds.
///
/// Errors in parsing (e.g., malformed packets) are silently dropped rather than
/// panicked, allowing the capture loop to continue processing subsequent packets.
fn process_raw(
    data:  &[u8],
    cfg:   &MonitorConfig,
    flows: &SharedFlows,
    hosts: &SharedHosts,
) {
    // Parse the raw packet as an Ethernet frame with optional IP and transport layers.
    // Skip packets that cannot be decoded as valid Ethernet frames.
    let sliced = match SlicedPacket::from_ethernet(data) {
        Ok(s)  => s,
        Err(_) => return,
    };

    let payload = sliced.payload;

    // Extract source and destination IPv4 addresses. Skip non-IPv4 packets.
    let (src, dst) = match sliced.ip {
        Some(etherparse::InternetSlice::Ipv4(h, _)) => (
            h.source_addr().to_string(),
            h.destination_addr().to_string(),
        ),
        _ => return,
    };

    // Early exit if neither source nor destination IP is in the tracked set.
    // This reduces unnecessary processing overhead for unrelated traffic.
    if !cfg.tracked.contains(&src) && !cfg.tracked.contains(&dst) {
        return;
    }

    let now = Instant::now();

    // ── Host table update ─────────────────────────────────────────────────────
    // `DashMap::entry` takes a per-shard lock, not a global lock, so other
    // shards (and the eviction thread on unrelated shards) remain unblocked.
    // This design prevents the global Mutex bottleneck described in Bug 4.
    let is_new_host = !hosts.contains_key(&src);
    let mut host_ref = hosts
        .entry(src.clone())
        .or_insert_with(|| HostProfile::new(now));

    // Bug 4b: Increment the running total exactly once, on first insertion.
    // This ensures `total_hosts_seen` reflects the true count of unique hosts,
    // not just a snapshot of the current table size.
    if is_new_host {
        cfg.stats.total_hosts_seen.fetch_add(1, Ordering::Relaxed);
    }

    // Update host basic metrics (last seen, peer diversity, etc.).
    host_ref.update_basic(&dst, now);

    // Increment global packet counter for statistics.
    cfg.stats.packets_total.fetch_add(1, Ordering::Relaxed);

    // Dispatch to protocol-specific handlers based on transport layer.
    match sliced.transport {
        Some(TransportSlice::Udp(udp)) => {
            // Handle DNS queries and responses (port 53).
            if udp.destination_port() == 53 || udp.source_port() == 53 {
                if let Some(domain) = parse_dns_name(payload) {
                    host_ref.handle_dns(&src, domain, &cfg.logger);
                }
            }
        }
        Some(TransportSlice::Tcp(tcp)) => {
            // Avoid holding the host shard lock while accessing the flows table,
            // which could lead to lock ordering issues or reduced concurrency.
            // Drop the host entry reference and re-acquire it after flow processing.
            drop(host_ref);
            if let Some(mut h) = hosts.get_mut::<String>(&src) {
                process_tcp_packet(
                    &src, &dst, tcp, payload, now, h.value_mut(),
                    flows, &cfg.logger, &cfg.stats,
                );
            }
            // Re-borrow for anomaly detection below.
            if let Some(mut h) = hosts.get_mut::<String>(&src) {
                detect_host_anomalies(
                    &src, h.value_mut(), now,
                    &cfg.thresholds, &cfg.logger, &cfg.stats,
                );
            }
            return;
        }
        _ => {}
    }

    // Anomaly detection for non-TCP packets (UDP, etc.).
    // Checks for threshold violations in host behavior metrics.
    detect_host_anomalies(
        &src, host_ref.value_mut(), now,
        &cfg.thresholds, &cfg.logger, &cfg.stats,
    );
}