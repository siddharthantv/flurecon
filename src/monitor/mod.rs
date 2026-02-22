pub mod config;
pub mod types;
pub mod flow;
pub mod host;
pub mod detection;
pub mod parsers;

use crate::monitor::config::*;
use crate::monitor::detection::detect_host_anomalies;
use crate::monitor::flow::process_tcp_packet;
use crate::monitor::parsers::parse_dns_name;
use crate::monitor::types::*;

use etherparse::{SlicedPacket, TransportSlice};
use pcap::Capture;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

/// Entry point for the network monitoring engine.
///
/// Opens a live capture on the system's default network device in promiscuous mode
/// and processes packets in a tight loop. For each packet the pipeline is:
///
/// 1. **Parse** the Ethernet frame and extract the IPv4 source/destination addresses.
/// 2. **Filter** — skip packets that do not involve any address in `tracked`.
/// 3. **Update** the source host's [`HostProfile`] with per-packet metrics.
/// 4. **Dispatch** to protocol-specific handlers:
///    - UDP port 53 → DNS query extraction via [`parse_dns_name`].
///    - TCP → flow state machine and TLS SNI extraction via [`process_tcp_packet`].
/// 5. **Detect** host-level anomalies (port scans, SYN floods, lateral movement).
/// 6. **Evict** flows and host profiles that have exceeded their idle timeouts.
///
/// The function runs indefinitely until the capture device returns an error
/// (e.g. the interface goes down or the process is interrupted).
///
/// # Arguments
/// * `tracked` - Set of IP addresses whose traffic should be monitored. Packets
///   where neither source nor destination appears in this set are silently skipped.
pub fn start_monitor(tracked: &HashSet<String>) {
    // Open the default pcap device in promiscuous mode so we receive all frames
    // on the segment, not just those addressed to this machine's MAC address.
    let dev = pcap::Device::lookup()
        .expect("pcap lookup failed")
        .expect("no capture device");

    let mut cap = Capture::from_device(dev)
        .unwrap()
        .promisc(true)
        .open()
        .unwrap();

    // Two independent state tables, keyed by different granularities:
    // - `flows` tracks individual TCP connections (identified by the 4-tuple).
    // - `hosts` tracks aggregate behaviour per source IP across all connections.
    // Both are evicted on a rolling timeout at the bottom of the packet loop.
    let mut flows: HashMap<FlowKey, TcpFlow> = HashMap::new();
    let mut hosts: HashMap<String, HostProfile> = HashMap::new();

    println!("\n[+] Advanced Network Analysis Engine started\n");

    while let Ok(pkt) = cap.next_packet() {
        // Attempt to parse the raw bytes as an Ethernet II frame and walk up the
        // layer stack. Malformed or non-Ethernet frames are silently dropped.
        let sliced = match SlicedPacket::from_ethernet(pkt.data) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let payload = sliced.payload;

        // We only handle IPv4 for now; IPv6 and non-IP frames are skipped.
        let (src, dst) = match sliced.ip {
            Some(etherparse::InternetSlice::Ipv4(h, _)) => (
                h.source_addr().to_string(),
                h.destination_addr().to_string(),
            ),
            _ => continue,
        };

        // Early-exit filter: ignore traffic that doesn't involve a tracked host.
        // Checking both directions ensures we capture inbound responses as well
        // as outbound requests from monitored addresses.
        if !tracked.contains(&src) && !tracked.contains(&dst) {
            continue;
        }

        // Snapshot the current time once per packet and reuse it throughout this
        // iteration to keep timestamps consistent across flow and host updates.
        let now = Instant::now();

        // Retrieve or create the host profile for the packet's source address.
        // Profiles accumulate across packets, so state built up in earlier
        // iterations (SYN counts, queried domains, etc.) is preserved here.
        let host = hosts
            .entry(src.clone())
            .or_insert_with(|| HostProfile::new(now));

        // Record the destination contact and refresh `last_seen` before any
        // protocol-specific handling, so the host is always up to date even
        // if the transport layer handler returns early.
        host.update_basic(&dst, now);

        match sliced.transport {
            // DNS runs over UDP port 53. We parse the query name and hand it to
            // the host profile, which deduplicates and logs new domains.
            Some(TransportSlice::Udp(udp)) => {
                if udp.destination_port() == 53 || udp.source_port() == 53 {
                    if let Some(domain) = parse_dns_name(payload) {
                        host.handle_dns(&src, domain);
                    }
                }
            }

            // TCP packets are handed off to the flow processor, which maintains
            // the per-connection state machine and handles TLS SNI extraction,
            // retransmission detection, and handshake RTT measurement.
            Some(TransportSlice::Tcp(tcp)) => {
                process_tcp_packet(&src, &dst, tcp, payload, now, host, &mut flows);
            }

            // All other transport protocols (ICMP, IGMP, etc.) are not yet handled.
            _ => {}
        }

        // Run anomaly detection against the freshly updated host profile.
        // This is intentionally called after the transport handler so that any
        // state changes made during packet processing are visible to the detector.
        detect_host_anomalies(&src, host, now);

        // Evict entries that have been idle longer than their respective timeouts.
        // This is done inline rather than on a timer to avoid the complexity of a
        // separate cleanup thread, at the cost of doing a linear scan each packet.
        // For high-throughput deployments this should be moved to a periodic task.
        flows.retain(|_, f| f.last_seen.elapsed() < FLOW_TIMEOUT);
        hosts.retain(|_, h| h.last_seen.elapsed() < HOST_TIMEOUT);
    }
}