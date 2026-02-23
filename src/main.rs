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
use std::fs;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ── Discovered device ────────────────────────────────────────────────────────

/// A network device discovered via ARP during the initial LAN sweep.
struct Device {
    ip:     String,
    mac:    String,
    vendor: String,
    risk:   String,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    // ── CLI ──────────────────────────────────────────────────────────────────
    let cli = Cli::parse();

    // ── Shutdown flag ────────────────────────────────────────────────────────
    // `Arc<AtomicBool>` shared with the ctrlc handler, the monitor loop, and
    // the eviction thread. Any component can set it; all components poll it.
    let shutdown: ShutdownFlag = Arc::new(AtomicBool::new(false));
    let shutdown_ctrlc = Arc::clone(&shutdown);

    let session_start = Instant::now();

    // ── Structured logger ────────────────────────────────────────────────────
    let logger = Arc::new(
        Logger::new(cli.json, cli.log_file.as_deref())
            .expect("Failed to open log file"),
    );

    // ── Session statistics ───────────────────────────────────────────────────
    let stats = SessionStats::new();

    // ── OUI database ─────────────────────────────────────────────────────────
    logger.log(&Event::Info { message: "Loading OUI database..." });
    let oui_db = load_oui_db();
    logger.log(&Event::Info {
        message: &format!("Loaded {} vendors", oui_db.len()),
    });

    // ── PCAP replay mode: skip ARP scan entirely ──────────────────────────────
    // In replay mode there is no live interface to scan. We let the monitor
    // engine discover tracked IPs from the packet stream itself.
    if cli.pcap_file.is_some() {
        logger.log(&Event::Info {
            message: "Replay mode active — skipping ARP scan",
        });
        let shutdown_ctrlc2 = Arc::clone(&shutdown);

        // Register Ctrl+C handler before handing off to the monitor.
        register_shutdown_handler(
            shutdown_ctrlc,
            Arc::clone(&logger),
            Arc::clone(&stats),
            session_start,
        );

        let cfg = MonitorConfig {
            tracked:        HashSet::new(), // populated from file by run_replay
            thresholds:     build_thresholds(&cli),
            logger:         Arc::clone(&logger),
            stats:          Arc::clone(&stats),
            shutdown:       Arc::clone(&shutdown_ctrlc2),
            pcap_file:      cli.pcap_file.clone(),
            evict_interval: cli.evict_interval,
        };

        start_monitor(cfg);
        print_summary(&logger, &stats, session_start);
        return;
    }

    // ── Interface selection ───────────────────────────────────────────────────
    // Honour --interface if given; otherwise pick the first usable one.
    let ifaces = get_if_addrs().unwrap();
    let mut my_ip:         Option<Ipv4Addr> = None;
    let mut my_iface_name: Option<String>   = None;
    let mut my_prefix_len: u8              = 24; // fallback if we can't derive it

    for iface in &ifaces {
        // Filter to the requested interface name if --interface was supplied.
        if let Some(ref wanted) = cli.interface {
            if &iface.name != wanted {
                continue;
            }
        }

        if let IfAddr::V4(v4) = &iface.addr {
            let ip = v4.ip;
            if ip.is_loopback() || ip.is_link_local() {
                continue;
            }
            my_ip         = Some(ip);
            my_iface_name = Some(iface.name.clone());

            // ── Derived subnet mask ───────────────────────────────────────────
            // get_if_addrs 0.5.x exposes the netmask as a bare Ipv4Addr.
            // Count leading 1-bits to derive the CIDR prefix length
            // (e.g. 255.255.255.0 -> /24, 255.255.0.0 -> /16).
            my_prefix_len = v4.netmask
                .octets()
                .iter()
                .map(|o: &u8| o.count_ones() as u8)
                .sum();
            break;
        }
    }

    let my_ip       = my_ip.expect("No usable IPv4 interface found");
    let iface_name  = my_iface_name.unwrap();

    logger.log(&Event::Info {
        message: &format!("Using IP: {} / prefix: /{}", my_ip, my_prefix_len),
    });
    logger.log(&Event::Info {
        message: &format!("Interface: {}", iface_name),
    });

    // Resolve the pnet interface descriptor.
    let interfaces = datalink::interfaces();
    let interface  = interfaces
        .into_iter()
        .find(|i| i.name == iface_name)
        .expect("Interface not found");

    let my_mac = interface.mac.unwrap();
    logger.log(&Event::Info {
        message: &format!("MAC: {}", my_mac),
    });

    // Open the raw Ethernet channel.
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        _ => panic!("Failed to open datalink channel"),
    };

    // ── ARP scan ──────────────────────────────────────────────────────────────
    // Derive the host range from the actual prefix length.
    // For a /24 this produces 1..=254 as before; for a /16 it produces all
    // 65534 host addresses in the subnet. Very large subnets (< /16) are
    // capped to avoid flooding the network.
    logger.log(&Event::Info { message: "Scanning LAN..." });
    let scan_targets = derive_scan_targets(my_ip, my_prefix_len);

    for target_ip in &scan_targets {
        send_arp_request(&mut tx, my_mac, my_ip, *target_ip);
    }

    // ── ARP reply collection ─────────────────────────────────────────────────
    let mut devices: Vec<Device> = Vec::new();
    let start = Instant::now();
    let arp_window = Duration::from_secs(cli.arp_timeout);

    while start.elapsed() < arp_window {
        if let Ok(packet) = rx.next() {
            if let Some(eth) = EthernetPacket::new(packet) {
                if eth.get_ethertype() == EtherTypes::Arp {
                    if let Some(arp) = ArpPacket::new(eth.payload()) {
                        if arp.get_operation() == ArpOperations::Reply {
                            let ip = arp.get_sender_proto_addr();
                            if ip == my_ip {
                                continue;
                            }

                            let mac     = arp.get_sender_hw_addr();
                            let mac_str = mac.to_string().to_uppercase();
                            let oui     = &mac_str[0..8];

                            let vendor = oui_db
                                .get(oui)
                                .map(|s| s.as_str())
                                .unwrap_or("Randomized / Spoofed");

                            let risk = if vendor == "Randomized / Spoofed" {
                                "Medium"
                            } else {
                                "Low"
                            };

                            // Log each discovered host through the structured logger.
                            logger.log(&Event::HostDiscovered {
                                ip:     &ip.to_string(),
                                mac:    &mac_str,
                                vendor,
                                risk,
                            });

                            devices.push(Device {
                                ip:     ip.to_string(),
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

    // Print the human-readable discovery table (always, regardless of --json).
    print_table(&devices);

    // ── Register Ctrl+C handler ───────────────────────────────────────────────
    register_shutdown_handler(
        shutdown_ctrlc,
        Arc::clone(&logger),
        Arc::clone(&stats),
        session_start,
    );

    // ── Hand off to monitor ───────────────────────────────────────────────────
    let mut tracked: HashSet<String> = HashSet::new();
    for d in &devices {
        tracked.insert(d.ip.clone());
    }

    let cfg = MonitorConfig {
        tracked,
        thresholds:     build_thresholds(&cli),
        logger:         Arc::clone(&logger),
        stats:          Arc::clone(&stats),
        shutdown:       Arc::clone(&shutdown),
        pcap_file:      None,
        evict_interval: cli.evict_interval,
    };

    start_monitor(cfg);

    // Reached when the monitor loop exits (shutdown flag set).
    print_summary(&logger, &stats, session_start);
}

// ── Shutdown handler ──────────────────────────────────────────────────────────

/// Registers the Ctrl+C / SIGINT handler.
///
/// On signal receipt the handler sets the shutdown flag, which causes the
/// monitor loop and eviction thread to exit at the next iteration. It does
/// NOT print the summary itself — that is done by `main` after
/// `start_monitor` returns, so the summary is always printed exactly once and
/// after any in-flight packets have been processed.
fn register_shutdown_handler(
    shutdown:      ShutdownFlag,
    _logger:       Arc<Logger>,
    _stats:        Arc<monitor::types::SessionStats>,
    _session_start: Instant,
) {
    ctrlc::set_handler(move || {
        println!("\n[!] Ctrl+C received — shutting down...");
        shutdown.store(true, Ordering::SeqCst);
    })
    .expect("Failed to register Ctrl+C handler");
}

// ── Session summary ───────────────────────────────────────────────────────────

/// Prints the end-of-session summary via the structured logger.
///
/// Called by `main` after `start_monitor` returns, ensuring it runs exactly
/// once regardless of whether shutdown was triggered by Ctrl+C or EOF (replay
/// mode). All values are read from the atomic counters in [`SessionStats`].
fn print_summary(
    logger:        &Arc<Logger>,
    stats:         &Arc<monitor::types::SessionStats>,
    session_start:  Instant,
) {
    let duration = session_start.elapsed().as_secs();
    logger.log(&Event::SessionSummary {
        duration_secs:  duration,
        hosts_seen:     stats.hosts_seen.load(Ordering::Relaxed)   as usize,
        flows_tracked:  stats.flows_tracked.load(Ordering::Relaxed) as usize,
        packets_total:  stats.packets_total.load(Ordering::Relaxed),
        alerts_emitted: stats.alerts_emitted.load(Ordering::Relaxed),
    });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Derives the list of host addresses to ARP-scan from the interface IP and
/// the actual prefix length read from the OS (not hardcoded as /24).
///
/// Subnets smaller than /16 (> 65534 hosts) are not enumerated to avoid
/// flooding the network; a warning is printed instead.
fn derive_scan_targets(ip: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    if prefix < 16 {
        println!(
            "[!] Subnet /{} is very large. Limiting scan to the /24 \
             containing this host. Use --interface to select a smaller subnet.",
            prefix
        );
        return derive_scan_targets(ip, 24);
    }

    let host_bits = 32u32 - prefix as u32;
    let host_count = (1u32 << host_bits) - 2; // exclude network and broadcast
    let mask = !((1u32 << host_bits) - 1);
    let base = u32::from(ip) & mask;

    (1..=host_count)
        .map(|i| Ipv4Addr::from(base + i))
        .collect()
}

/// Builds a [`Thresholds`] from CLI arguments.
fn build_thresholds(cli: &Cli) -> Thresholds {
    Thresholds {
        port_scan:     cli.port_scan_threshold,
        dos_syn_rate:  cli.dos_syn_rate,
        dos_half_open: cli.dos_half_open,
        lateral:       cli.lateral_threshold,
    }
}

/// Prints the ARP discovery table to stdout (always plain-text, for readability).
fn print_table(devices: &[Device]) {
    println!("\nDiscovered Devices:");
    println!("{:<16} {:<20} {:<30} {:<10}", "IP", "MAC", "Vendor", "Risk");
    println!("{}", "-".repeat(80));
    for d in devices {
        println!(
            "{:<16} {:<20} {:<30} {:<10}",
            d.ip, d.mac, d.vendor, d.risk
        );
    }
    println!();
}

/// Parses the IEEE OUI flat-file database into a prefix→vendor map.
fn load_oui_db() -> HashMap<String, String> {
    let data = fs::read_to_string("oui.txt").expect("Missing oui.txt");
    let mut map = HashMap::new();
    for line in data.lines() {
        if line.contains("(hex)") {
            let parts: Vec<&str> = line.split("(hex)").collect();
            let oui    = parts[0].trim().replace("-", ":");
            let vendor = parts[1].trim().to_string();
            map.insert(oui, vendor);
        }
    }
    map
}

/// Constructs and sends a single ARP request broadcast frame.
fn send_arp_request(
    tx:        &mut Box<dyn datalink::DataLinkSender>,
    my_mac:    MacAddr,
    my_ip:     Ipv4Addr,
    target_ip: Ipv4Addr,
) {
    let mut buffer = [0u8; 42];
    {
        let mut eth = MutableEthernetPacket::new(&mut buffer).unwrap();
        eth.set_destination(MacAddr::broadcast());
        eth.set_source(my_mac);
        eth.set_ethertype(EtherTypes::Arp);

        let mut arp = MutableArpPacket::new(eth.payload_mut()).unwrap();
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
    tx.send_to(&buffer, None);
}
