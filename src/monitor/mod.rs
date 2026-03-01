//! Network monitoring engine entry point.
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
    /// Network interface name for live capture.
    ///
    /// **Bug 5 fix:** When `Some`, `run_live` opens this specific device rather than letting
    /// libpcap pick the default. Must match the interface resolved in `main`.
    /// `None` falls back to `pcap::Device::lookup()`.
    pub iface_name:     Option<String>,
}

/// Entry point for the monitoring engine.
///
/// Initializes shared data structures and spawns background threads for packet
/// processing and entry eviction. Routes traffic to either live capture or PCAP
/// file replay based on the supplied configuration.
///
/// **Bug 6 fix:** Returns `Err(String)` if the capture device cannot be opened or the PCAP
/// file cannot be read, instead of panicking.
///
/// # Arguments
///
/// * `cfg` - Monitoring configuration including interfaces, thresholds, and file paths
///
/// # Returns
///
/// `Ok(())` on successful shutdown, or `Err(String)` describing why capture failed
pub fn start_monitor(cfg: MonitorConfig) -> Result<(), String> {
    // **Bug 4 fix:** Both tables are now `Arc<DashMap<_,_>>` for per-shard locking.
    // This allows the monitor thread and eviction thread to operate concurrently
    // with minimal contention.
    let flows: SharedFlows = Arc::new(DashMap::new());
    let hosts: SharedHosts = Arc::new(DashMap::new());

    // Spawn the background eviction thread to clean up aged-out entries while
    // the main thread processes packets.
    let eviction_handle = spawn_eviction_thread(
        Arc::clone(&flows),
        Arc::clone(&hosts),
        cfg.evict_interval,
        Arc::clone(&cfg.shutdown),
    );

    cfg.logger.log(&Event::Info {
        message: "Advanced Network Analysis Engine started",
    });

    // Route to appropriate input: PCAP file replay or live packet capture.
    let result = if let Some(ref path) = cfg.pcap_file {
        run_replay(path, &cfg, &flows, &hosts)
    } else {
        run_live(&cfg, &flows, &hosts)
    };

    // Wait for the eviction thread to finish.
    let _ = eviction_handle.join();
    result
}

// ── Live capture ──────────────────────────────────────────────────────────────

/// Opens a promiscuous live pcap capture on the configured interface.
///
/// Processes packets in a tight loop until shutdown is signaled, checking the
/// shutdown flag periodically via the pcap timeout mechanism. Packet processing
/// is delegated to the shared `process_raw` pipeline.
///
/// **Bug 5 fix:** Uses `cfg.iface_name` when set, rather than always calling
/// `Device::lookup()` which ignored the `--interface` CLI flag entirely.
///
/// # Arguments
///
/// * `cfg` - Configuration including interface name and shutdown signal
/// * `flows` - Shared flow table (Arc<DashMap>)
/// * `hosts` - Shared host table (Arc<DashMap>)
///
/// # Returns
///
/// `Ok(())` on clean shutdown, or `Err(String)` if device cannot be opened
fn run_live(
    cfg:   &MonitorConfig,
    flows: &SharedFlows,
    hosts: &SharedHosts,
) -> Result<(), String> {
    // Open the capture device. If a specific interface was requested, use it;
    // otherwise fall back to libpcap's default device selection.
    let mut cap = if let Some(ref name) = cfg.iface_name {
        // **Bug 5 fix:** Open the specific interface the user requested via CLI.
        Capture::from_device(name.as_str())
            .map_err(|e| format!("Cannot open interface '{}': {}", name, e))?
            .promisc(true)
            .timeout(200)   // wake every 200ms so shutdown flag is checked promptly
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
            .timeout(200)   // wake every 200ms so shutdown flag is checked promptly
            .open()
            .map_err(|e| format!("Cannot start capture: {}", e))?
    };

    // Main packet capture loop. Process each incoming packet and periodically
    // check the shutdown flag via timeout expiration.
    while !cfg.shutdown.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(pkt)  => process_raw(pkt.data, cfg, flows, hosts),
            Err(pcap::Error::TimeoutExpired) => continue, // woke up to check shutdown flag
            Err(_)   => break,
        }
    }

    Ok(())
}

// ── PCAP file replay ──────────────────────────────────────────────────────────

/// Opens an offline PCAP file and replays every packet through the pipeline.
///
/// Useful for deterministic testing and analysis of captured traffic. Processes
/// packets sequentially until EOF or shutdown is signaled.
///
/// **Bug 6 fix:** Returns `Err` instead of panicking when the file cannot be opened.
///
/// # Arguments
///
/// * `path` - Path to the PCAP file to replay
/// * `cfg` - Configuration including shutdown signal
/// * `flows` - Shared flow table (Arc<DashMap>)
/// * `hosts` - Shared host table (Arc<DashMap>)
///
/// # Returns
///
/// `Ok(())` on successful completion, or `Err(String)` if file cannot be opened
fn run_replay(
    path:  &str,
    cfg:   &MonitorConfig,
    flows: &SharedFlows,
    hosts: &SharedHosts,
) -> Result<(), String> {
    cfg.logger.log(&Event::Info {
        message: "Replay mode: reading from PCAP file",
    });

    // **Bug 6 fix:** Use `map_err` to propagate file open errors instead of panicking.
    let mut cap = Capture::from_file(path)
        .map_err(|e| format!("Failed to open PCAP file '{}': {}", path, e))?;

    // Replay loop: process each packet in the file until EOF or shutdown.
    while !cfg.shutdown.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(pkt) => process_raw(pkt.data, cfg, flows, hosts),
            Err(_)  => break,
        }
    }

    Ok(())
}

// ── Shared packet processing pipeline ────────────────────────────────────────

/// Decodes and processes a raw Ethernet frame through the anomaly detection pipeline.
///
/// Extracts IPv4 headers, filters to tracked hosts, updates the host profile,
/// dispatches to protocol-specific handlers (DNS/TCP), and triggers anomaly
/// detection heuristics.
///
/// # Arguments
///
/// * `data` - Raw Ethernet frame bytes
/// * `cfg` - Configuration including tracked IPs and detection thresholds
/// * `flows` - Shared flow table for TCP session tracking
/// * `hosts` - Shared host table for profile updates
fn process_raw(
    data:  &[u8],
    cfg:   &MonitorConfig,
    flows: &SharedFlows,
    hosts: &SharedHosts,
) {
    // Parse the Ethernet frame and extract layers. Silently drop malformed packets.
    let sliced = match SlicedPacket::from_ethernet(data) {
        Ok(s)  => s,
        Err(_) => return,
    };

    let payload = sliced.payload;

    // Extract source and destination IP addresses. We only support IPv4 at this time.
    let (src, dst) = match sliced.ip {
        Some(etherparse::InternetSlice::Ipv4(h, _)) => (
            h.source_addr().to_string(),
            h.destination_addr().to_string(),
        ),
        _ => return,
    };

    // Early exit if neither endpoint is in our tracked set. This reduces memory
    // footprint in environments where only a small subnet is monitored.
    if !cfg.tracked.contains(&src) && !cfg.tracked.contains(&dst) {
        return;
    }

    let now = Instant::now();

    // ── Host table update ─────────────────────────────────────────────────────
    // **Bug 4 fix:** `DashMap::entry` takes a per-shard lock, not a global lock, so other
    // shards (and the eviction thread on unrelated shards) remain unblocked.
    let is_new_host = !hosts.contains_key(&src);
    let mut host_ref = hosts
        .entry(src.clone())
        .or_insert_with(|| HostProfile::new(now));

    // **Bug 4b fix:** Increment the running total exactly once, on first insertion.
    if is_new_host {
        cfg.stats.total_hosts_seen.fetch_add(1, Ordering::Relaxed);
    }

    // Update the host profile with basic connectivity information.
    host_ref.update_basic(&dst, now);

    // Track total packet count for statistical summaries.
    cfg.stats.packets_total.fetch_add(1, Ordering::Relaxed);

    // Dispatch to protocol-specific handlers based on the transport layer.
    match sliced.transport {
        Some(TransportSlice::Udp(udp)) => {
            // Detect and extract DNS queries/responses on port 53.
            if udp.destination_port() == 53 || udp.source_port() == 53 {
                if let Some(domain) = parse_dns_name(payload) {
                    host_ref.handle_dns(&src, domain, &cfg.logger);
                }
            }
        }
        Some(TransportSlice::Tcp(tcp)) => {
            // Drop the host entry ref before calling process_tcp_packet to
            // avoid holding a DashMap shard lock across the flows table access.
            drop(host_ref);
            
            // Process TCP packets: track connections, detect port scanning, etc.
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

    // Anomaly detection for non-TCP packets (UDP, ICMP, etc.). Checks thresholds
    // like request rate, unique destinations, and other behavioral signals.
    detect_host_anomalies(
        &src, host_ref.value_mut(), now,
        &cfg.thresholds, &cfg.logger, &cfg.stats,
    );
}