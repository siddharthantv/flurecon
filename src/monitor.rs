use etherparse::{SlicedPacket, TransportSlice};
use pcap::Capture;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/* ================= CONFIG ================= */

const FLOW_TIMEOUT: Duration = Duration::from_secs(120);
const HOST_TIMEOUT: Duration = Duration::from_secs(60);

const PORT_SCAN_WINDOW: Duration = Duration::from_secs(30);
const DOS_WINDOW: Duration = Duration::from_secs(5);
const SLOW_RTT: Duration = Duration::from_millis(500);

/* ================= STRUCTS ================= */

#[derive(Hash, Eq, PartialEq, Debug)]
struct FlowKey {
    a_ip: String,
    a_port: u16,
    b_ip: String,
    b_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpState {
    Syn,
    SynAck,
    Established,
    Fin,
    Reset,
}

struct TcpFlow {
    state: TcpState,
    syn_time: Instant,
    last_seq: u32,
    last_ack: u32,
    last_window: u16,
    dup_ack: u32,
    retransmits: u32,
    last_seen: Instant,
}

struct HostProfile {
    syn_times: VecDeque<Instant>,
    ports: HashSet<u16>,
    targets: HashSet<String>,
    dns_queries: HashSet<String>,
    tls_sni: HashSet<String>,
    half_open: u32,
    rst_count: u32,
    packet_count: u64,
    last_seen: Instant,
}

/* ================= MAIN ================= */

pub fn start_monitor(tracked: &HashSet<String>) {
    let dev = pcap::Device::lookup()
        .expect("pcap lookup failed")
        .expect("no capture device");

    let mut cap = Capture::from_device(dev)
        .unwrap()
        .promisc(true)
        .open()
        .unwrap();

    let mut flows: HashMap<FlowKey, TcpFlow> = HashMap::new();
    let mut hosts: HashMap<String, HostProfile> = HashMap::new();

    println!("\n[+] Advanced Network Analysis Engine started\n");

    while let Ok(pkt) = cap.next_packet() {
        let sliced = match SlicedPacket::from_ethernet(pkt.data) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let payload = sliced.payload;

        let (src, dst) = match sliced.ip {
            Some(etherparse::InternetSlice::Ipv4(h, _)) => (
                h.source_addr().to_string(),
                h.destination_addr().to_string(),
            ),
            _ => continue,
        };

        if !tracked.contains(&src) && !tracked.contains(&dst) {
            continue;
        }

        let now = Instant::now();

        let host = hosts.entry(src.clone()).or_insert(HostProfile {
            syn_times: VecDeque::new(),
            ports: HashSet::new(),
            targets: HashSet::new(),
            dns_queries: HashSet::new(),
            tls_sni: HashSet::new(),
            half_open: 0,
            rst_count: 0,
            packet_count: 0,
            last_seen: now,
        });

        host.packet_count += 1;
        host.targets.insert(dst.clone());
        host.last_seen = now;

        /* ================= TRANSPORT (SINGLE MATCH) ================= */

        match sliced.transport {
            Some(TransportSlice::Udp(udp)) => {
                /* ---------- DNS ---------- */
                if udp.destination_port() == 53 || udp.source_port() == 53 {
                    if let Some(domain) = parse_dns_name(payload) {
                        if host.dns_queries.insert(domain.clone()) {
                            println!("[DNS] {} queried {}", src, domain);
                        }
                    }
                }
            }

            Some(TransportSlice::Tcp(tcp)) => {
                /* ---------- FLOW KEY ---------- */

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

                /* ---------- TCP STATE ---------- */

                if tcp.syn() && !tcp.ack() {
                    flow.state = TcpState::Syn;
                    flow.syn_time = now;
                    host.syn_times.push_back(now);
                    host.ports.insert(tcp.destination_port());
                    host.half_open += 1;
                } else if tcp.syn() && tcp.ack() {
                    flow.state = TcpState::SynAck;
                    let rtt = now.duration_since(flow.syn_time);
                    if rtt > SLOW_RTT {
                        println!(
                            "[SLOW HANDSHAKE] {}:{} → {}:{} RTT={}ms",
                            src,
                            tcp.source_port(),
                            dst,
                            tcp.destination_port(),
                            rtt.as_millis()
                        );
                    }
                } else if tcp.ack() && flow.state == TcpState::SynAck {
                    flow.state = TcpState::Established;
                    host.half_open = host.half_open.saturating_sub(1);
                }

                if tcp.fin() {
                    flow.state = TcpState::Fin;
                }
                if tcp.rst() {
                    flow.state = TcpState::Reset;
                    host.rst_count += 1;
                }

                /* ---------- RETRANSMISSION ---------- */

                if seq == flow.last_seq {
                    flow.retransmits += 1;
                }

                /* ---------- ACK ---------- */

                if ack == flow.last_ack {
                    flow.dup_ack += 1;
                    if flow.dup_ack >= 3 {
                        println!("[DUP ACK] {} ack={}", src, ack);
                    }
                } else if ack > flow.last_ack {
                    flow.dup_ack = 0;
                }

                /* ---------- WINDOW ---------- */

                if win == 0 {
                    println!("[ZERO WINDOW] {}:{}", src, tcp.source_port());
                }

                /* ---------- TLS SNI ---------- */

                if tcp.destination_port() == 443 || tcp.source_port() == 443 {
                    if let Some(sni) = parse_tls_sni(payload) {
                        if host.tls_sni.insert(sni.clone()) {
                            println!("[TLS SNI] {} → {}", src, sni);
                        }
                    }
                }

                flow.last_seq = seq;
                flow.last_ack = ack;
                flow.last_window = win;
                flow.last_seen = now;
            }

            _ => {}
        }

        /* ================= HOST-LEVEL DETECTION ================= */

        while let Some(t) = host.syn_times.front() {
            if now.duration_since(*t) > PORT_SCAN_WINDOW {
                host.syn_times.pop_front();
            } else {
                break;
            }
        }

        if host.ports.len() >= 15 {
            println!("[PORT SCAN] {} scanned {} ports", src, host.ports.len());
        }

        let syn_rate = host.syn_times.len() as f32 / DOS_WINDOW.as_secs_f32();
        if syn_rate > 20.0 && host.half_open > 10 {
            println!(
                "[DoS] {} SYN rate {:.1}/s half-open {}",
                src, syn_rate, host.half_open
            );
        }

        if host.targets.len() >= 10 {
            println!(
                "[LATERAL MOVEMENT] {} contacted {} internal hosts",
                src,
                host.targets.len()
            );
        }

        if host.packet_count > 10_000 {
            println!("[BEHAVIORAL DEVIATION] {}", src);
        }

        flows.retain(|_, f| f.last_seen.elapsed() < FLOW_TIMEOUT);
        hosts.retain(|_, h| h.last_seen.elapsed() < HOST_TIMEOUT);
    }
}

/* ================= PARSERS ================= */

fn parse_dns_name(payload: &[u8]) -> Option<String> {
    if payload.len() < 12 {
        return None;
    }

    let mut idx = 12;
    let mut name = String::new();

    while idx < payload.len() {
        let len = payload[idx] as usize;
        if len == 0 || idx + len + 1 > payload.len() {
            break;
        }
        if !name.is_empty() {
            name.push('.');
        }
        idx += 1;
        name.push_str(std::str::from_utf8(&payload[idx..idx + len]).ok()?);
        idx += len;
    }

    if name.is_empty() { None } else { Some(name) }
}

fn parse_tls_sni(payload: &[u8]) -> Option<String> {
    if payload.len() < 43 || payload[0] != 0x16 {
        return None;
    }

    let mut i = 43;
    while i + 9 < payload.len() {
        if payload[i] == 0x00 && payload[i + 1] == 0x00 {
            let len =
                ((payload[i + 7] as usize) << 8) | payload[i + 8] as usize;
            let start = i + 9;
            if start + len <= payload.len() {
                return std::str::from_utf8(&payload[start..start + len])
                    .ok()
                    .map(|s| s.to_string());
            }
            break;
        }
        i += 1;
    }
    None
}

