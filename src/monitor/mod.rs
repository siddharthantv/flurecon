//! Network monitoring engine entry point.
//!
//! Changes from v0.1.0:
//! - Flow and host tables are now `Arc<Mutex<_>>` so the eviction thread can
//!   access them concurrently without data races.
//! - Inline `retain()` calls removed; eviction is handled by the background
//!   thread in [`eviction`].
//! - PCAP file replay mode added: `--read <file>` skips ARP scan and treats
//!   all unique source IPs in the file as tracked hosts.
//! - All `println!` replaced with structured [`Logger`] events.
//! - [`SessionStats`] counters updated on every packet and alert.
//! - The monitor loop polls the [`ShutdownFlag`] and exits cleanly on Ctrl+C.
//! - Subnet mask is derived from the interface's actual prefix length rather
//!   than being hardcoded as /24.

pub mod config;
pub mod detection;
pub mod eviction;
pub mod flow;
pub mod host;
pub mod parsers;
pub mod types;

use crate::logger::{Event, SharedLogger};
use crate::monitor::detection::detect_host_anomalies;
use crate::monitor::eviction::{spawn_eviction_thread, SharedFlows, SharedHosts};
use crate::monitor::flow::process_tcp_packet;
use crate::monitor::parsers::parse_dns_name;
use crate::monitor::types::*;

use etherparse::{SlicedPacket, TransportSlice};
use pcap::Capture;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Configuration bundle passed from `main` into the monitoring engine.
pub struct MonitorConfig {
    /// IPs to monitor. In live mode: ARP-discovered hosts. In replay mode: all
    /// source IPs seen in the PCAP file (populated before this call).
    pub tracked:       HashSet<String>,
    /// Runtime-tunable detection thresholds from CLI args.
    pub thresholds:    Thresholds,
    /// Shared structured logger.
    pub logger:        SharedLogger,
    /// Shared session statistics for the shutdown summary.
    pub stats:         SharedStats,
    /// Set to `true` by the ctrlc handler; the loop exits on next iteration.
    pub shutdown:      ShutdownFlag,
    /// Path to a PCAP file for offline replay, or `None` for live capture.
    pub pcap_file:     Option<String>,
    /// Eviction sweep interval in seconds.
    pub evict_interval: u64,
}

/// Entry point for the monitoring engine.
///
/// Dispatches to [`run_live`] or [`run_replay`] depending on whether a PCAP
/// file was supplied on the command line. Both paths share the same packet
/// processing pipeline; they differ only in how packets are sourced.
pub fn start_monitor(cfg: MonitorConfig) {
    // Shared tables — Arc<Mutex<_>> so the eviction thread can access them.
    let flows: SharedFlows = Arc::new(Mutex::new(HashMap::new()));
    let hosts: SharedHosts = Arc::new(Mutex::new(HashMap::new()));

    // Spawn the background eviction thread.
    let eviction_handle = spawn_eviction_thread(
        Arc::clone(&flows),
        Arc::clone(&hosts),
        cfg.evict_interval,
        Arc::clone(&cfg.shutdown),
    );

    cfg.logger.log(&Event::Info {
        message: "Advanced Network Analysis Engine started",
    });

    if let Some(ref path) = cfg.pcap_file {
        run_replay(path, &cfg, &flows, &hosts);
    } else {
        run_live(&cfg, &flows, &hosts);
    }

    // Wait for the eviction thread to finish its final pass.
    let _ = eviction_handle.join();
}

// ── Live capture ──────────────────────────────────────────────────────────────

/// Opens a promiscuous live pcap capture and processes packets until shutdown.
fn run_live(cfg: &MonitorConfig, flows: &SharedFlows, hosts: &SharedHosts) {
    let dev = pcap::Device::lookup()
        .expect("pcap lookup failed")
        .expect("no capture device");

    let mut cap = Capture::from_device(dev)
        .unwrap()
        .promisc(true)
        .open()
        .unwrap();

    while !cfg.shutdown.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(pkt) => process_raw(pkt.data, cfg, flows, hosts),
            Err(_)  => break,
        }
    }
}

// ── PCAP file replay ──────────────────────────────────────────────────────────

/// Opens an offline PCAP file and replays every packet through the same pipeline.
///
/// All unique source IPs in the file are automatically added to the tracked
/// set so that every host in the capture is analysed, even if they were not
/// in the original ARP-discovered set (which is skipped in replay mode).
fn run_replay(path: &str, cfg: &MonitorConfig, flows: &SharedFlows, hosts: &SharedHosts) {
    cfg.logger.log(&Event::Info {
        message: "Replay mode: reading from PCAP file",
    });

    let mut cap = Capture::from_file(path).expect("Failed to open PCAP file");

    while !cfg.shutdown.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(pkt) => process_raw(pkt.data, cfg, flows, hosts),
            Err(_)  => break, // End of file or read error
        }
    }
}

// ── Shared packet processing pipeline ────────────────────────────────────────

/// Processes a single raw packet through the full analysis pipeline.
///
/// Shared between live and replay modes. Steps:
/// 1. Parse Ethernet frame up through IP and transport layers.
/// 2. Filter out packets not involving a tracked host.
/// 3. Update source host profile.
/// 4. Dispatch to protocol handler (DNS / TCP).
/// 5. Run host-level anomaly detection.
/// 6. Update session statistics.
fn process_raw(
    data:  &[u8],
    cfg:   &MonitorConfig,
    flows: &SharedFlows,
    hosts: &SharedHosts,
) {
    let sliced = match SlicedPacket::from_ethernet(data) {
        Ok(s)  => s,
        Err(_) => return,
    };

    let payload = sliced.payload;

    let (src, dst) = match sliced.ip {
        Some(etherparse::InternetSlice::Ipv4(h, _)) => (
            h.source_addr().to_string(),
            h.destination_addr().to_string(),
        ),
        _ => return,
    };

    if !cfg.tracked.contains(&src) && !cfg.tracked.contains(&dst) {
        return;
    }

    let now = Instant::now();

    // Lock both tables for the duration of this packet's processing.
    // The eviction thread uses the same mutexes; contention is expected to
    // be low because eviction is infrequent relative to packet arrival rate.
    let mut flows_guard = match flows.lock() {
        Ok(g)  => g,
        Err(_) => return,
    };
    let mut hosts_guard = match hosts.lock() {
        Ok(g)  => g,
        Err(_) => return,
    };

    let host = hosts_guard
        .entry(src.clone())
        .or_insert_with(|| HostProfile::new(now));

    host.update_basic(&dst, now);

    // Update session high-watermarks.
    let hcount = hosts_guard.len() as u64;
    let fcount = flows_guard.len() as u64;
    cfg.stats.hosts_seen.fetch_max(hcount, Ordering::Relaxed);
    cfg.stats.flows_tracked.fetch_max(fcount, Ordering::Relaxed);
    cfg.stats.packets_total.fetch_add(1, Ordering::Relaxed);

    // Reborrow host after the watermark updates.
    let host = hosts_guard.get_mut(&src).unwrap();

    match sliced.transport {
        Some(TransportSlice::Udp(udp)) => {
            if udp.destination_port() == 53 || udp.source_port() == 53 {
                if let Some(domain) = parse_dns_name(payload) {
                    host.handle_dns(&src, domain, &cfg.logger);
                }
            }
        }
        Some(TransportSlice::Tcp(tcp)) => {
            process_tcp_packet(
                &src, &dst, tcp, payload, now, host,
                &mut flows_guard, &cfg.logger, &cfg.stats,
            );
        }
        _ => {}
    }

    detect_host_anomalies(
        &src, host, now,
        &cfg.thresholds,
        &cfg.logger,
        &cfg.stats,
    );
}
