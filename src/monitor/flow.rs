//! TCP flow state machine and per-flow anomaly detection.
//!
//! This module implements a stateful TCP flow tracker that monitors individual
//! flows for anomalies including retransmissions, duplicate ACKs, zero-window
//! conditions, and slow handshakes. Flow state transitions follow the standard
//! TCP lifecycle (SYN → SYN-ACK → ESTABLISHED → FIN/RST).
//!
//! ## Notable Implementation Details
//!
//! - **Zero Window Tracking**: Moved from per-flow boolean to `host.zero_window_ports`
//!   HashSet<u16>. The per-flow bool approach failed because tools like nmap create
//!   a fresh flow entry per port, resetting the flag each time. Keying on dst_port
//!   in the host profile ensures at most one alert per unique (src, dst_port) pair.
//! - **Duplicate ACK Counter**: Reset to 0 immediately after alerting instead of
//!   using a boolean flag, preventing alert spam during sustained retransmit bursts.
//! - **TcpFlow Struct**: No longer maintains `zero_window_alerted` or `dup_ack_alerted`
//!   fields; state is managed at the host profile level.

use crate::logger::{Event, SharedLogger};
use crate::monitor::config::*;
use crate::monitor::parsers::parse_tls_sni;
use crate::monitor::types::*;
use dashmap::DashMap;
use etherparse::TcpHeaderSlice;
use std::sync::atomic::Ordering;
use std::time::Instant;

/// Processes a single TCP packet, updating the flow table and host profile.
///
/// This function serves as the main entry point for TCP packet processing. It:
/// 1. Canonicalizes the flow key to ensure bidirectional flows map to a single entry
/// 2. Inserts or retrieves the flow state from the global flow table
/// 3. Executes state machine transitions based on TCP flags
/// 4. Detects transport anomalies (retransmissions, duplicate ACKs, zero window)
/// 5. Extracts TLS SNI for HTTPS traffic
/// 6. Updates flow metadata for future packet matching
pub fn process_tcp_packet(
    src:     &String,
    dst:     &String,
    tcp:     TcpHeaderSlice,
    payload: &[u8],
    now:     Instant,
    host:    &mut HostProfile,
    flows:   &DashMap<FlowKey, TcpFlow>,
    logger:  &SharedLogger,
    stats:   &SharedStats,
) {
    // ── Flow Key Canonicalization ────────────────────────────────────────────
    // Normalize the flow tuple so that both directions of a flow map to the same
    // entry. This avoids duplicate tracking and halves the memory footprint.
    let mut key = FlowKey {
        a_ip:   src.clone(),
        a_port: tcp.source_port(),
        b_ip:   dst.clone(),
        b_port: tcp.destination_port(),
    };

    if key.a_ip > key.b_ip {
        std::mem::swap(&mut key.a_ip, &mut key.b_ip);
        std::mem::swap(&mut key.a_port, &mut key.b_port);
    }

    let seq = tcp.sequence_number();
    let ack = tcp.acknowledgment_number();
    let win = tcp.window_size();

    // ── Flow Insertion ───────────────────────────────────────────────────────
    // Insert a new flow entry if this is the first packet we've seen for this
    // (src, dst) pair, or retrieve the existing entry for state updates.
    let is_new_flow = !flows.contains_key(&key);
    let mut flow_entry = flows.entry(key).or_insert(TcpFlow {
        state:       TcpState::Syn,
        syn_time:    now,
        last_seq:    seq,
        last_ack:    ack,
        last_window: win,
        dup_ack:     0,
        retransmits: 0,
        last_seen:   now,
    });

    if is_new_flow {
        stats.total_flows_tracked.fetch_add(1, Ordering::Relaxed);
    }

    let flow = flow_entry.value_mut();

    // ── TCP State Machine ────────────────────────────────────────────────────
    // Track the TCP connection lifecycle. Most packets advance the state machine;
    // anomaly detection occurs independently (below).
    
    if tcp.syn() && !tcp.ack() {
        flow.state    = TcpState::Syn;
        flow.syn_time = now;
        host.syn_times.push_back(now);
        host.dos_syn_times.push_back(now);
        host.ports.insert(tcp.destination_port());
        host.half_open += 1;
    }

    if tcp.syn() && tcp.ack() {
        flow.state = TcpState::SynAck;
        // Measure round-trip time (RTT) from SYN to SYN-ACK. Unusually long RTTs
        // may indicate slow networks, congestion, or suspicious behavior.
        let rtt = now.duration_since(flow.syn_time);
        if rtt > SLOW_RTT {
            logger.log(&Event::SlowHandshake { src, rtt_ms: rtt.as_millis() });
            stats.alerts_emitted.fetch_add(1, Ordering::Relaxed);
        }
    }

    if tcp.ack() && flow.state == TcpState::SynAck {
        flow.state     = TcpState::Established;
        host.half_open = host.half_open.saturating_sub(1);
    }

    if tcp.fin() { flow.state = TcpState::Fin; }
    if tcp.rst() {
        flow.state     = TcpState::Reset;
        host.rst_count += 1;
    }

    // ── Transport Anomalies ──────────────────────────────────────────────────
    // Detect retransmissions, duplicate ACKs, and zero-window conditions.
    // These are indicative of congestion, packet loss, or malicious activity.
    
    if seq == flow.last_seq {
        flow.retransmits += 1;
    }

    if ack == flow.last_ack {
        flow.dup_ack += 1;
        // Alert on the fast-retransmit trigger (3 consecutive duplicate ACKs).
        // Per TCP congestion control (RFC 5681), 3 dup-ACKs signal packet loss.
        // Reset the counter immediately to avoid re-alerting on the same burst.
        if flow.dup_ack >= 3 {
            logger.log(&Event::DupAck { src, ack });
            stats.alerts_emitted.fetch_add(1, Ordering::Relaxed);
            flow.dup_ack = 0;
        }
    } else if ack > flow.last_ack {
        // Forward progress on ACK means we've left the duplicate window.
        flow.dup_ack = 0;
    }

    if win == 0 {
        // Detect zero-window advertisements, which pause transmission.
        // Alert once per unique destination port per source host.
        // A per-flow boolean failed because tools like nmap create a new TcpFlow
        // per port, resetting the flag each time. host.zero_window_ports is a
        // HashSet that persists across flows, ensuring each (src_host, dst_port)
        // pair only alerts once.
        let dst_port = tcp.destination_port();
        if host.zero_window_ports.insert(dst_port) {
            logger.log(&Event::ZeroWindow { src, port: dst_port });
            stats.alerts_emitted.fetch_add(1, Ordering::Relaxed);
        }
    }

    // ── TLS SNI Extraction ───────────────────────────────────────────────────
    // Extract the Server Name Indication (SNI) from TLS ClientHello messages
    // for HTTPS traffic (port 443). SNI enables host-based profiling and
    // detection of suspicious domain requests.
    if tcp.destination_port() == 443 || tcp.source_port() == 443 {
        if let Some(sni) = parse_tls_sni(payload) {
            host.handle_tls(src, sni, logger);
        }
    }

    // ── Update Flow State ────────────────────────────────────────────────────
    // Record the latest sequence, acknowledgment, and window values to enable
    // change detection in future packets.
    flow.last_seq    = seq;
    flow.last_ack    = ack;
    flow.last_window = win;
    flow.last_seen   = now;
}