mod cli;
mod logger;
mod monitor;

use cli::Cli;
use clap::Parser;
use get_if_addrs::{get_if_addrs, IfAddr};
use logger::{Event, Logger};
use monitor::types::{SessionStats, ShutdownFlag, Thresholds};
use monitor::{MonitorConfig, start_monitor};
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Represents a discovered device on the network.
struct Device {
    ip:     String,
    mac:    String,
    vendor: String,
    risk:   String,
}

fn main() {
    // Parse command-line arguments
    let cli = Cli::parse();

    // Initialize shutdown flag for graceful termination
    let shutdown: ShutdownFlag = Arc::new(AtomicBool::new(false));
    let shutdown_ctrlc = Arc::clone(&shutdown);

    // Track session duration for summary reporting
    let session_start = Instant::now();

    // Initialize logger with optional JSON output and file logging
    let logger = Arc::new(
        Logger::new(cli.json, cli.log_file.as_deref())
            .expect("Failed to open log file"),
    );

    // Create session statistics tracker
    let stats = SessionStats::new();

    // ── OUI database ─────────────────────────────────────────────────────────
    // Load IEEE OUI (Organizationally Unique Identifier) database for vendor
    // lookup. Bug 6 fix: load_oui_db now returns Result; log a warning and
    // continue with an empty map rather than panicking if the file is missing.
    logger.log(&Event::Info { message: "Loading OUI database..." });
    let oui_db = match load_oui_db() {
        Ok(db) => {
            logger.log(&Event::Info {
                message: &format!("Loaded {} vendors", db.len()),
            });
            db
        }
        Err(e) => {
            logger.log(&Event::Info {
                message: &format!(
                    "Warning: could not load oui.txt ({}). Vendor lookup disabled.",
                    e
                ),
            });
            HashMap::new()
        }
    };

    // ── PCAP replay mode ──────────────────────────────────────────────────────
    // If a PCAP file is provided, skip live ARP scanning and replay from file
    if cli.pcap_file.is_some() {
        logger.log(&Event::Info {
            message: "Replay mode active — skipping ARP scan",
        });

        register_shutdown_handler(shutdown_ctrlc, Arc::clone(&logger));

        let cfg = MonitorConfig {
            tracked:        HashSet::new(),
            thresholds:     build_thresholds(&cli),
            logger:         Arc::clone(&logger),
            stats:          Arc::clone(&stats),
            shutdown:       Arc::clone(&shutdown),
            pcap_file:      cli.pcap_file.clone(),
            evict_interval: cli.evict_interval,
            iface_name:     None,
        };

        if let Err(e) = start_monitor(cfg) {
            logger.log(&Event::Info {
                message: &format!("Monitor error: {}", e),
            });
        }
        print_summary(&logger, &stats, session_start);
        return;
    }

    // ── Interface selection ───────────────────────────────────────────────────
    // Enumerate available network interfaces and select the target interface
    // for ARP scanning. Filter out loopback and link-local addresses.
    let ifaces = get_if_addrs().unwrap();
    let mut my_ip:         Option<Ipv4Addr> = None;
    let mut my_iface_name: Option<String>   = None;
    let mut my_prefix_len: u8              = 24;

    for iface in &ifaces {
        if let Some(ref wanted) = cli.interface {
            if &iface.name != wanted { continue; }
        }
        if let IfAddr::V4(v4) = &iface.addr {
            let ip = v4.ip;
            if ip.is_loopback() || ip.is_link_local() { continue; }
            my_ip         = Some(ip);
            my_iface_name = Some(iface.name.clone());
            my_prefix_len = v4.netmask
                .octets()
                .iter()
                .map(|o| o.count_ones() as u8)
                .sum();
            break;
        }
    }

    let my_ip      = my_ip.expect("No usable IPv4 interface found");
    let iface_name = my_iface_name.unwrap();

    logger.log(&Event::Info {
        message: &format!("Using IP: {} / prefix: /{}", my_ip, my_prefix_len),
    });
    logger.log(&Event::Info { message: &format!("Interface: {}", iface_name) });

    // Resolve the network interface handle for packet transmission/reception
    let interfaces = datalink::interfaces();
    let interface  = interfaces
        .into_iter()
        .find(|i| i.name == iface_name)
        .expect("Interface not found");

    let my_mac = interface.mac.unwrap();
    logger.log(&Event::Info { message: &format!("MAC: {}", my_mac) });

    // Open datalink channel for raw packet I/O
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        _ => panic!("Failed to open datalink channel"),
    };

    // ── ARP scan ──────────────────────────────────────────────────────────────
    // Perform active ARP scanning across the local subnet to discover hosts.
    // Derives target IP list from network address and prefix, then sends
    // ARP requests with configurable rate-limiting to avoid network flooding.
    logger.log(&Event::Info { message: "Scanning LAN..." });
    let scan_targets = derive_scan_targets(my_ip, my_prefix_len);
    let arp_rate_delay = Duration::from_millis(cli.arp_rate_ms);

    logger.log(&Event::Info {
        message: &format!(
            "Sending {} ARP requests (inter-packet delay: {}ms)",
            scan_targets.len(),
            cli.arp_rate_ms,
        ),
    });

    for target_ip in &scan_targets {
        if let Err(e) = send_arp_request(&mut tx, my_mac, my_ip, *target_ip) {
            logger.log(&Event::Info {
                message: &format!("ARP send failed for {}: {}", target_ip, e),
            });
        }
        // Rate-limit: pause between frames to avoid flooding the network.
        // At the default of 1 ms this is ~1000 pkts/sec — safe for any
        // modern LAN yet quiet enough to avoid triggering IDS alerts.
        // Users can set --arp-rate 0 to restore the original burst behaviour.
        if cli.arp_rate_ms > 0 {
            std::thread::sleep(arp_rate_delay);
        }
    }

    // ── ARP reply collection ──────────────────────────────────────────────────
    // Collect ARP replies from discovered hosts within the configured timeout
    // window. Dedup on (IP, MAC) pairs to handle proxy-ARP devices correctly
    // while filtering duplicate replies from the same host.
    let mut devices: Vec<Device> = Vec::new();
    // Dedup key is (IP, MAC) — a host reporting two different MACs for the
    // same IP (e.g. a proxy-ARP device) gets one entry per unique pair, while
    // duplicate replies from the same host are silently dropped.
    let mut seen: HashSet<(String, String)> = HashSet::new();

    let start      = Instant::now();
    let arp_window = Duration::from_secs(cli.arp_timeout);

    while start.elapsed() < arp_window {
        if let Ok(packet) = rx.next() {
            if let Some(eth) = EthernetPacket::new(packet) {
                if eth.get_ethertype() == EtherTypes::Arp {
                    if let Some(arp) = ArpPacket::new(eth.payload()) {
                        if arp.get_operation() == ArpOperations::Reply {
                            let ip = arp.get_sender_proto_addr();
                            if ip == my_ip { continue; }

                            let ip_str  = ip.to_string();
                            let mac     = arp.get_sender_hw_addr();
                            let mac_str = mac.to_string().to_uppercase();

                            // Dedup on (IP, MAC): drops duplicate replies from
                            // the same host while preserving proxy-ARP entries
                            // that legitimately report different MACs for the
                            // same IP.
                            if !seen.insert((ip_str.clone(), mac_str.clone())) {
                                continue;
                            }
                            let oui     = &mac_str[0..8];

                            // Perform vendor lookup using OUI prefix
                            let vendor = oui_db
                                .get(oui)
                                .map(|s| s.as_str())
                                .unwrap_or("Randomized / Spoofed");

                            // Assign risk level based on vendor classification
                            let risk = if vendor == "Randomized / Spoofed" {
                                "Medium"
                            } else {
                                "Low"
                            };

                            logger.log(&Event::HostDiscovered {
                                ip: &ip_str,
                                mac: &mac_str,
                                vendor,
                                risk,
                            });

                            devices.push(Device {
                                ip:     ip_str,
                                mac:    mac_str,
                                vendor: vendor.to_string(),
                                risk:   risk.to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    // Display discovered devices in tabular format
    print_table(&devices);

    register_shutdown_handler(shutdown_ctrlc, Arc::clone(&logger));

    // ── Network monitoring phase ──────────────────────────────────────────────
    // Track discovered hosts for anomaly detection and threat monitoring
    let mut tracked: HashSet<String> = HashSet::new();
    for d in &devices { tracked.insert(d.ip.clone()); }

    let cfg = MonitorConfig {
        tracked,
        thresholds:     build_thresholds(&cli),
        logger:         Arc::clone(&logger),
        stats:          Arc::clone(&stats),
        shutdown:       Arc::clone(&shutdown),
        pcap_file:      None,
        evict_interval: cli.evict_interval,
        // Bug 5 fix: pass the resolved interface name so run_live opens it
        // instead of letting pcap pick its own default device.
        iface_name:     Some(iface_name),
    };

    if let Err(e) = start_monitor(cfg) {
        logger.log(&Event::Info {
            message: &format!("Monitor error: {}", e),
        });
    }

    print_summary(&logger, &stats, session_start);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Registers a signal handler for graceful shutdown on Ctrl+C
fn register_shutdown_handler(shutdown: ShutdownFlag, _logger: Arc<Logger>) {
    ctrlc::set_handler(move || {
        println!("\n[!] Ctrl+C received — shutting down...");
        shutdown.store(true, Ordering::SeqCst);
    })
    .expect("Failed to register Ctrl+C handler");
}

/// Prints session summary statistics including duration, host count, and alerts
fn print_summary(
    logger:        &Arc<Logger>,
    stats:         &Arc<monitor::types::SessionStats>,
    session_start:  Instant,
) {
    let duration = session_start.elapsed().as_secs();
    logger.log(&logger::Event::SessionSummary {
        duration_secs:  duration,
        // Bug 4b fix: use the renamed fields that represent running totals.
        hosts_seen:     stats.total_hosts_seen.load(Ordering::Relaxed)    as usize,
        flows_tracked:  stats.total_flows_tracked.load(Ordering::Relaxed) as usize,
        packets_total:  stats.packets_total.load(Ordering::Relaxed),
        alerts_emitted: stats.alerts_emitted.load(Ordering::Relaxed),
    });
}

/// Derives a list of target IP addresses for ARP scanning from network prefix.
/// Recursively limits large subnets (< /16) to /24 to avoid excessive scanning.
fn derive_scan_targets(ip: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    if prefix < 16 {
        println!(
            "[!] Subnet /{} is very large. Limiting scan to the /24 containing this host.",
            prefix
        );
        return derive_scan_targets(ip, 24);
    }
    let host_bits = 32u32 - prefix as u32;
    let host_count = (1u32 << host_bits) - 2;
    let mask = !((1u32 << host_bits) - 1);
    let base = u32::from(ip) & mask;
    (1..=host_count).map(|i| Ipv4Addr::from(base + i)).collect()
}

/// Builds threshold configuration from command-line arguments
fn build_thresholds(cli: &Cli) -> Thresholds {
    Thresholds {
        port_scan:     cli.port_scan_threshold,
        dos_syn_rate:  cli.dos_syn_rate,
        dos_half_open: cli.dos_half_open,
        lateral:       cli.lateral_threshold,
    }
}

/// Prints discovered devices in tabular format with columns for IP, MAC, vendor, and risk
fn print_table(devices: &[Device]) {
    println!("\nDiscovered Devices:");
    println!("{:<16} {:<20} {:<30} {:<10}", "IP", "MAC", "Vendor", "Risk");
    println!("{}", "-".repeat(80));
    for d in devices {
        println!("{:<16} {:<20} {:<30} {:<10}", d.ip, d.mac, d.vendor, d.risk);
    }
    println!();
}

/// Parses the IEEE OUI flat-file database into a prefix→vendor map.
/// Bug 6 fix: returns `Result` instead of panicking on a missing file.
fn load_oui_db() -> Result<HashMap<String, String>, String> {
    let data = std::fs::read_to_string("oui.txt")
        .map_err(|e| format!("cannot read oui.txt: {}", e))?;
    let mut map = HashMap::new();
    for line in data.lines() {
        if line.contains("(hex)") {
            let parts: Vec<&str> = line.split("(hex)").collect();
            let oui    = parts[0].trim().replace("-", ":");
            let vendor = parts[1].trim().to_string();
            map.insert(oui, vendor);
        }
    }
    Ok(map)
}

/// Constructs and sends a single ARP request broadcast frame.
/// Bug 6 fix: returns `Result` so the caller can log send failures.
/// Previously `tx.send_to()` returned `Option<io::Result<()>>` and the
/// result was silently discarded.
fn send_arp_request(
    tx:        &mut Box<dyn datalink::DataLinkSender>,
    my_mac:    MacAddr,
    my_ip:     Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Result<(), String> {
    let mut buffer = [0u8; 42];
    {
        let mut eth = MutableEthernetPacket::new(&mut buffer)
            .ok_or("Failed to create Ethernet packet")?;
        eth.set_destination(MacAddr::broadcast());
        eth.set_source(my_mac);
        eth.set_ethertype(EtherTypes::Arp);

        let mut arp = MutableArpPacket::new(eth.payload_mut())
            .ok_or("Failed to create ARP packet")?;
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(my_mac);
        arp.set_sender_proto_addr(my_ip);
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(target_ip);
    }

    match tx.send_to(&buffer, None) {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(format!("{}", e)),
        None         => Err("send_to returned None (no packet sent)".to_string()),
    }
}