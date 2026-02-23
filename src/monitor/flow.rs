//! TCP flow state machine and per-flow anomaly detection.
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
/// See the v0.1.0 documentation for the full description of this function's
/// role. The only behavioural change is that all output now goes through the
/// structured logger and alert events increment the session stats counter.
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
    if tcp.syn() && !tcp.ack() {
        flow.state    = TcpState::Syn;
        flow.syn_time = now;
        host.syn_times.push_back(now);
        host.ports.insert(tcp.destination_port());
        host.half_open += 1;
    }

    if tcp.syn() && tcp.ack() {
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
        flow.state    = TcpState::Established;
        host.half_open = host.half_open.saturating_sub(1);
    }

    if tcp.fin() {
        flow.state = TcpState::Fin;
    }

    if tcp.rst() {
        flow.state     = TcpState::Reset;
        host.rst_count += 1;
    }

    // ── Transport Anomalies ──────────────────────────────────────────────────
    if seq == flow.last_seq {
        flow.retransmits += 1;
    }

    if ack == flow.last_ack {
        flow.dup_ack += 1;
        if flow.dup_ack >= 3 {
            logger.log(&Event::DupAck { src, ack });
            stats.alerts_emitted.fetch_add(1, Ordering::Relaxed);
        }
    } else if ack > flow.last_ack {
        flow.dup_ack = 0;
    }

    if win == 0 {
        logger.log(&Event::ZeroWindow {
            src,
            port: tcp.source_port(),
        });
        stats.alerts_emitted.fetch_add(1, Ordering::Relaxed);
    }

    // ── TLS SNI Extraction ───────────────────────────────────────────────────
    if tcp.destination_port() == 443 || tcp.source_port() == 443 {
        if let Some(sni) = parse_tls_sni(payload) {
            host.handle_tls(src, sni, logger);
        }
    }

    // ── Update Flow State ────────────────────────────────────────────────────
    flow.last_seq    = seq;
    flow.last_ack    = ack;
    flow.last_window = win;
    flow.last_seen   = now;
}
