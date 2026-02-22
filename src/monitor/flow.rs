use crate::monitor::config::*;
use crate::monitor::parsers::parse_tls_sni;
use crate::monitor::types::*;
use etherparse::TcpHeaderSlice;
use std::collections::HashMap;
use std::time::Instant;

/// Processes a single TCP packet, updating the corresponding flow state and host profile.
///
/// This function is the core of the TCP tracking pipeline. For each packet it:
/// - Looks up or creates a bidirectional [`TcpFlow`] entry keyed by the canonical (sorted) endpoint pair.
/// - Advances the flow's state machine through the standard TCP lifecycle (SYN → SYN-ACK → Established → FIN/RST).
/// - Detects and records anomalies: slow handshakes, retransmissions, duplicate ACKs, and zero-window conditions.
/// - Extracts the TLS SNI hostname from HTTPS payloads and forwards it to the host profile.
///
/// # Arguments
/// * `src`    - Source IP address of the packet as a string.
/// * `dst`    - Destination IP address of the packet as a string.
/// * `tcp`    - Parsed TCP header providing flags, ports, sequence/acknowledgment numbers, and window size.
/// * `payload`- TCP payload bytes, used for TLS SNI extraction on port 443.
/// * `now`    - Timestamp of the packet, used for RTT calculation and flow aging.
/// * `host`   - Mutable reference to the [`HostProfile`] associated with the source, updated with
///              SYN timing, open ports, RST counts, and TLS hostnames.
/// * `flows`  - Shared flow table mapping [`FlowKey`]s to their [`TcpFlow`] tracking state.
pub fn process_tcp_packet(
    src: &String,
    dst: &String,
    tcp: TcpHeaderSlice,
    payload: &[u8],
    now: Instant,
    host: &mut HostProfile,
    flows: &mut HashMap<FlowKey, TcpFlow>,
) {
    // Build a canonical, direction-agnostic flow key by ensuring the lexicographically
    // smaller IP always occupies the `a_ip` slot. This allows both directions of a
    // connection to map to the same entry in the flow table.
    let mut key = FlowKey {
        a_ip: src.clone(),
        a_port: tcp.source_port(),
        b_ip: dst.clone(),
        b_port: tcp.destination_port(),
    };

    if key.a_ip > key.b_ip {
        std::mem::swap(&mut key.a_ip, &mut key.b_ip);
        std::mem::swap(&mut key.a_port, &mut key.b_port);
    }

    let seq = tcp.sequence_number();
    let ack = tcp.acknowledgment_number();
    let win = tcp.window_size();

    // Retrieve the existing flow or insert a new one initialised at the SYN state.
    // `syn_time` is set here as a placeholder; it is overwritten when the actual SYN is processed below.
    let flow = flows.entry(key).or_insert(TcpFlow {
        state: TcpState::Syn,
        syn_time: now,
        last_seq: seq,
        last_ack: ack,
        last_window: win,
        dup_ack: 0,
        retransmits: 0,
        last_seen: now,
    });

    // ── TCP State Machine ────────────────────────────────────────────────────────

    // SYN (no ACK): the initiating side is opening a new connection.
    // Record the timestamp for RTT measurement and track the destination port
    // to detect port scanning behaviour on the host profile.
    if tcp.syn() && !tcp.ack() {
        flow.state = TcpState::Syn;
        flow.syn_time = now;
        host.syn_times.push_back(now);
        host.ports.insert(tcp.destination_port());
        host.half_open += 1;
    }

    // SYN-ACK: the remote side is acknowledging the connection request.
    // Measure the round-trip time from the original SYN; flag it if it exceeds the
    // configured `SLOW_RTT` threshold, which may indicate congestion or a distant peer.
    if tcp.syn() && tcp.ack() {
        flow.state = TcpState::SynAck;
        let rtt = now.duration_since(flow.syn_time);
        if rtt > SLOW_RTT {
            println!("[SLOW HANDSHAKE] {} RTT={}ms", src, rtt.as_millis());
        }
    }

    // ACK while in SYN-ACK state: the three-way handshake is complete.
    // Decrement the half-open counter now that the connection is fully established.
    if tcp.ack() && flow.state == TcpState::SynAck {
        flow.state = TcpState::Established;
        host.half_open = host.half_open.saturating_sub(1);
    }

    // FIN: one side is initiating an orderly shutdown of the connection.
    if tcp.fin() {
        flow.state = TcpState::Fin;
    }

    // RST: the connection is being aborted unconditionally.
    // A high RST rate on a host can indicate port scans, firewall rejections, or application errors.
    if tcp.rst() {
        flow.state = TcpState::Reset;
        host.rst_count += 1;
    }

    // ── Anomaly Detection ────────────────────────────────────────────────────────

    // Retransmission: the sender is repeating a segment with the same sequence number,
    // indicating the original was lost or not acknowledged in time.
    if seq == flow.last_seq {
        flow.retransmits += 1;
    }

    // Duplicate ACK: the receiver is repeatedly acknowledging the same byte offset,
    // which typically signals an out-of-order or missing segment upstream.
    // Three or more consecutive duplicate ACKs triggers TCP fast retransmit on the sender side.
    if ack == flow.last_ack {
        flow.dup_ack += 1;
        if flow.dup_ack >= 3 {
            println!("[DUP ACK] {} ack={}", src, ack);
        }
    } else if ack > flow.last_ack {
        // New data acknowledged; reset the duplicate ACK counter.
        flow.dup_ack = 0;
    }

    // Zero-window: the receiver's buffer is full and it cannot accept more data.
    // Sustained zero-window conditions can cause significant throughput stalls.
    if win == 0 {
        println!("[ZERO WINDOW] {}:{}", src, tcp.source_port());
    }

    // ── TLS SNI Extraction ───────────────────────────────────────────────────────

    // For HTTPS traffic (port 443), attempt to extract the SNI hostname from the
    // TLS ClientHello. The SNI is sent in plaintext before the encrypted handshake
    // completes, making it available for visibility without decryption.
    if tcp.destination_port() == 443 || tcp.source_port() == 443 {
        if let Some(sni) = parse_tls_sni(payload) {
            host.handle_tls(src, sni);
        }
    }

    // ── Update Flow Tracking State ───────────────────────────────────────────────

    // Persist the current packet's fields so the next packet in this flow can
    // detect retransmissions, duplicate ACKs, and window changes by comparison.
    flow.last_seq = seq;
    flow.last_ack = ack;
    flow.last_window = win;
    flow.last_seen = now;
}