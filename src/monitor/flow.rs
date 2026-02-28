//! TCP flow state machine and per-flow anomaly detection.
//!
//! This module processes individual TCP packets and maintains flow state for
//! anomaly detection. Each flow is uniquely identified by a bidirectional tuple
//! of (IP, port) pairs, normalized so that the lower IP address is always 'a'.
//!
//! Key responsibilities:
//! - Track TCP handshake progression (SYN → SYN-ACK → ACT)
//! - Detect transport-layer anomalies (retransmissions, duplicate ACKs, zero windows)
//! - Extract TLS SNI for HTTPS traffic classification
//! - Maintain per-host statistics for downstream detection modules
//!
//! Changes from previous version:
//! - SYN packets now push a timestamp onto both `host.dos_syn_times` and
//!   `host.syn_times`. `dos_syn_times` is evicted to `DOS_WINDOW` (5 s) in
//!   `detection.rs` and used exclusively for the DoS SYN-rate calculation,
//!   fixing the inflated-rate bug where `syn_times` (30 s window) was divided
//!   by the 5-second `DOS_WINDOW`.

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
/// # Arguments
/// * `src` - Source IP address
/// * `dst` - Destination IP address
/// * `tcp` - Parsed TCP header
/// * `payload` - TCP payload data
/// * `now` - Current timestamp
/// * `host` - Mutable reference to the source host's profile
/// * `flows` - Concurrent flow table indexed by bidirectional flow key
/// * `logger` - Shared event logger for anomalies
/// * `stats` - Shared statistics counters
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
    // Normalize flow key: ensure lower IP is always 'a' for bidirectional matching
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

    // Extract TCP header fields for state tracking
    let seq = tcp.sequence_number();
    let ack = tcp.acknowledgment_number();
    let win = tcp.window_size();

    // Create or retrieve existing flow entry
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

    // Increment total flows counter when a genuinely new flow is created.
    if is_new_flow {
        stats.total_flows_tracked.fetch_add(1, Ordering::Relaxed);
    }

    let flow = flow_entry.value_mut();

    // ── TCP Handshake State Machine ──────────────────────────────────────────
    // Track the three-way handshake and connection lifecycle states.
    if tcp.syn() && !tcp.ack() {
        // SYN: Initial connection request from client
        flow.state    = TcpState::Syn;
        flow.syn_time = now;

        // Push to both sliding windows for rate-based DoS detection:
        //   syn_times     → bounded to PORT_SCAN_WINDOW (30 s) in detection.rs
        //   dos_syn_times → bounded to DOS_WINDOW (5 s) in detection.rs
        host.syn_times.push_back(now);
        host.dos_syn_times.push_back(now);

        host.ports.insert(tcp.destination_port());
        host.half_open += 1;
    }

    if tcp.syn() && tcp.ack() {
        // SYN-ACK: Server response acknowledging the SYN
        flow.state = TcpState::SynAck;
        let rtt = now.duration_since(flow.syn_time);
        if rtt > SLOW_RTT {
            logger.log(&Event::SlowHandshake {
                src,
                rtt_ms: rtt.as_millis(),
            });
            stats.alerts_emitted.fetch_add(1, Ordering::Relaxed);
        }
    }

    if tcp.ack() && flow.state == TcpState::SynAck {
        // ACK: Client acknowledges SYN-ACK, connection established
        flow.state     = TcpState::Established;
        host.half_open = host.half_open.saturating_sub(1);
    }

    if tcp.fin() {
        // FIN: Graceful connection termination
        flow.state = TcpState::Fin;
    }
    
    if tcp.rst() {
        // RST: Abrupt connection reset
        flow.state     = TcpState::Reset;
        host.rst_count += 1;
    }

    // ── Transport-Layer Anomaly Detection ────────────────────────────────────
    // Detect packet loss, congestion, and flow control violations.
    if seq == flow.last_seq {
        // Retransmission: same sequence number indicates packet retransmission
        flow.retransmits += 1;
    }

    if ack == flow.last_ack {
        // Duplicate ACK: same ACK number may indicate packet loss or network issues
        flow.dup_ack += 1;
        if flow.dup_ack >= 3 {
            logger.log(&Event::DupAck { src, ack });
            stats.alerts_emitted.fetch_add(1, Ordering::Relaxed);
        }
    } else if ack > flow.last_ack {
        // New ACK: reset counter when acknowledgment advances
        flow.dup_ack = 0;
    }

    if win == 0 {
        // Zero Window: receiver cannot accept more data (flow control violation)
        logger.log(&Event::ZeroWindow { src, port: tcp.source_port() });
        stats.alerts_emitted.fetch_add(1, Ordering::Relaxed);
    }

    // ── TLS SNI Extraction ───────────────────────────────────────────────────
    // Extract Server Name Indication (SNI) from TLS ClientHello for HTTPS flows.
    if tcp.destination_port() == 443 || tcp.source_port() == 443 {
        if let Some(sni) = parse_tls_sni(payload) {
            host.handle_tls(src, sni, logger);
        }
    }

    // ── Update Flow State ────────────────────────────────────────────────────
    // Store current packet values for anomaly detection in subsequent packets.
    flow.last_seq    = seq;
    flow.last_ack    = ack;
    flow.last_window = win;
    flow.last_seen   = now;
}