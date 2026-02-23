//! TCP flow state machine and per-flow anomaly detection.
//!
//! This module maintains per-flow TCP state and performs transport-layer
//! anomaly detection based on packet-level observations.
//!
//! Changes from v0.1.0:
//! - `println!` calls replaced with structured [`Logger`] events.
//! - [`SharedStats`] alert counter incremented for each transport-layer alert.
//! - Logger and stats are threaded through as parameters.

use crate::logger::{Event, SharedLogger};
use crate::monitor::config::*;
use crate::monitor::parsers::parse_tls_sni;
use crate::monitor::types::*;
use etherparse::TcpHeaderSlice;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::Instant;

/// Processes a single TCP packet, updating the flow table and host profile.
///
/// This function:
/// - Normalizes flow direction using a canonical key.
/// - Advances a simplified TCP state machine.
/// - Detects transport-layer anomalies (dup ACKs, retransmits, zero window).
/// - Extracts TLS SNI metadata when applicable.
/// - Updates per-flow tracking fields.
///
/// All alerts are emitted through the structured logger and increment
/// the shared session statistics counter.
pub fn process_tcp_packet(
    src:     &String,
    dst:     &String,
    tcp:     TcpHeaderSlice,
    payload: &[u8],
    now:     Instant,
    host:    &mut HostProfile,
    flows:   &mut HashMap<FlowKey, TcpFlow>,
    logger:  &SharedLogger,
    stats:   &SharedStats,
) {
    // Build canonical, direction-agnostic flow key.
    //
    // The goal is to ensure that traffic between A→B and B→A maps
    // to the same `FlowKey`. We normalize ordering lexicographically
    // based on IP address, swapping endpoints when necessary.
    let mut key = FlowKey {
        a_ip:   src.clone(),
        a_port: tcp.source_port(),
        b_ip:   dst.clone(),
        b_port: tcp.destination_port(),
    };

    // Enforce canonical ordering to make flow lookup symmetric.
    if key.a_ip > key.b_ip {
        std::mem::swap(&mut key.a_ip, &mut key.b_ip);
        std::mem::swap(&mut key.a_port, &mut key.b_port);
    }

    // Extract frequently used TCP header fields.
    let seq = tcp.sequence_number();
    let ack = tcp.acknowledgment_number();
    let win = tcp.window_size();

    // Insert flow if not present, initializing with SYN state.
    //
    // New flows begin in `TcpState::Syn` by default and are updated
    // as handshake packets are observed.
    let flow = flows.entry(key).or_insert(TcpFlow {
        state:       TcpState::Syn,
        syn_time:    now,
        last_seq:    seq,
        last_ack:    ack,
        last_window: win,
        dup_ack:     0,
        retransmits: 0,
        last_seen:   now,
    });

    // ── TCP State Machine ────────────────────────────────────────────────────
    //
    // Simplified TCP state tracking based on observed flags.

    // Initial SYN (connection initiation).
    if tcp.syn() && !tcp.ack() {
        flow.state    = TcpState::Syn;
        flow.syn_time = now;

        // Track SYN timestamps for host-level rate analysis.
        host.syn_times.push_back(now);

        // Record destination port for port-scan detection.
        host.ports.insert(tcp.destination_port());

        // Increment half-open connection counter.
        host.half_open += 1;
    }

    // SYN-ACK response from server.
    if tcp.syn() && tcp.ack() {
        flow.state = TcpState::SynAck;

        // Compute handshake RTT from initial SYN.
        let rtt = now.duration_since(flow.syn_time);

        // Flag slow handshakes exceeding configured threshold.
        if rtt > SLOW_RTT {
            logger.log(&Event::SlowHandshake {
                src,
                rtt_ms: rtt.as_millis(),
            });

            stats.alerts_emitted.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Final ACK completing the three-way handshake.
    if tcp.ack() && flow.state == TcpState::SynAck {
        flow.state = TcpState::Established;

        // Reduce half-open count safely (avoid underflow).
        host.half_open = host.half_open.saturating_sub(1);
    }

    // Connection teardown via FIN.
    if tcp.fin() {
        flow.state = TcpState::Fin;
    }

    // Abrupt termination via RST.
    if tcp.rst() {
        flow.state     = TcpState::Reset;

        // Track reset frequency at host level.
        host.rst_count += 1;
    }

    // ── Transport Anomalies ──────────────────────────────────────────────────
    //
    // Detect low-level TCP anomalies often associated with congestion,
    // packet loss, or malicious manipulation.

    // Retransmission detection: identical sequence number observed.
    if seq == flow.last_seq {
        flow.retransmits += 1;
    }

    // Duplicate ACK detection.
    if ack == flow.last_ack {
        flow.dup_ack += 1;

        // Triple duplicate ACK is a common retransmission trigger.
        if flow.dup_ack >= 3 {
            logger.log(&Event::DupAck { src, ack });
            stats.alerts_emitted.fetch_add(1, Ordering::Relaxed);
        }
    } else if ack > flow.last_ack {
        // Reset duplicate ACK counter on forward progress.
        flow.dup_ack = 0;
    }

    // Zero-window advertisement indicates receiver buffer exhaustion.
    if win == 0 {
        logger.log(&Event::ZeroWindow {
            src,
            port: tcp.source_port(),
        });

        stats.alerts_emitted.fetch_add(1, Ordering::Relaxed);
    }

    // ── TLS SNI Extraction ───────────────────────────────────────────────────
    //
    // If traffic involves port 443, attempt to extract TLS Server Name
    // Indication (SNI) from ClientHello payload.
    //
    // This enables host-level tracking of accessed domains.
    if tcp.destination_port() == 443 || tcp.source_port() == 443 {
        if let Some(sni) = parse_tls_sni(payload) {
            host.handle_tls(src, sni, logger);
        }
    }

    // ── Update Flow State ────────────────────────────────────────────────────
    //
    // Persist latest observed TCP values for next packet comparison.
    flow.last_seq    = seq;
    flow.last_ack    = ack;
    flow.last_window = win;
    flow.last_seen   = now;
}
