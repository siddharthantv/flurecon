mod monitor;

use get_if_addrs::{get_if_addrs, IfAddr};
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// A network device discovered via ARP during the LAN scan.
struct Device {
    /// IPv4 address of the device as reported in the ARP reply.
    ip: String,
    /// MAC address in uppercase colon-separated notation (e.g. `AA:BB:CC:DD:EE:FF`).
    mac: String,
    /// Vendor name resolved from the OUI database, or `"Randomized / Spoofed"` if unknown.
    vendor: String,
    /// Heuristic risk classification derived from vendor lookup (`"Low"` or `"Medium"`).
    risk: String,
}

fn main() {
    // ── OUI Database ─────────────────────────────────────────────────────────────

    // The OUI (Organisationally Unique Identifier) database maps the first three
    // octets of a MAC address to the registered hardware vendor. We use this to
    // flag devices with randomised or unregistered MACs as potentially suspicious.
    println!("[+] Loading OUI database...");
    let oui_db = load_oui_db();
    println!("[+] Loaded {} vendors", oui_db.len());

    // ── Interface Discovery ───────────────────────────────────────────────────────

    // Walk all network interfaces and pick the first non-loopback, non-link-local
    // IPv4 address. This gives us the host's LAN address and the interface name
    // needed to open a raw datalink channel.
    let ifaces = get_if_addrs().unwrap();
    let mut my_ip = None;
    let mut my_iface_name = None;

    for iface in ifaces {
        if let IfAddr::V4(v4) = iface.addr {
            let ip = v4.ip;
            if !ip.is_loopback() && !ip.is_link_local() {
                my_ip = Some(ip);
                my_iface_name = Some(iface.name);
                break;
            }
        }
    }

    let my_ip = my_ip.expect("No IP found");
    let iface_name = my_iface_name.unwrap();

    println!("Using IP: {}", my_ip);
    println!("Interface: {}", iface_name);

    // Resolve the pnet interface descriptor from the name we found above.
    // We need this to obtain the hardware MAC address and open the channel.
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|i| i.name == iface_name)
        .expect("Interface not found");

    let my_mac = interface.mac.unwrap();
    println!("My MAC: {}", my_mac);

    // Open a raw Ethernet channel. `tx` is used to send crafted ARP frames;
    // `rx` is used to receive all frames arriving on the interface.
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        _ => panic!("Failed to open datalink channel"),
    };

    // ── ARP Scan ─────────────────────────────────────────────────────────────────

    // Broadcast an ARP request to every host address in the local /24 subnet.
    // Hosts that are online will respond with their MAC address, which we collect
    // in the receive loop below. We assume a /24 mask; a production scanner would
    // derive the broadcast range from the interface's actual prefix length.
    println!("Scanning LAN...");

    for i in 1..=254 {
        let target_ip = Ipv4Addr::new(
            my_ip.octets()[0],
            my_ip.octets()[1],
            my_ip.octets()[2],
            i,
        );
        send_arp_request(&mut tx, my_mac, my_ip, target_ip);
    }

    // ── ARP Reply Collection ──────────────────────────────────────────────────────

    // Collect ARP replies for 3 seconds. This window is a trade-off: long enough
    // for slow or distant hosts to respond, short enough to keep startup latency
    // acceptable. Devices that do not reply within this window are not discovered.
    let mut devices: Vec<Device> = Vec::new();
    let start = Instant::now();

    while start.elapsed() < Duration::from_secs(3) {
        if let Ok(packet) = rx.next() {
            if let Some(eth) = EthernetPacket::new(packet) {
                if eth.get_ethertype() == EtherTypes::Arp {
                    if let Some(arp) = ArpPacket::new(eth.payload()) {
                        if arp.get_operation() == ArpOperations::Reply {
                            let ip = arp.get_sender_proto_addr();

                            // Skip replies from our own IP to avoid adding the
                            // host machine to the discovered device list.
                            if ip == my_ip {
                                continue;
                            }

                            let mac = arp.get_sender_hw_addr();
                            let mac_str = mac.to_string().to_uppercase();

                            // The OUI is the first 8 characters of the colon-separated
                            // MAC string (e.g. `AA:BB:CC`), matching the format used
                            // as keys in the OUI database loaded from `oui.txt`.
                            let oui = &mac_str[0..8];

                            let vendor = match oui_db.get(oui) {
                                Some(v) => v.as_str(),
                                // An unrecognised OUI typically indicates a randomised
                                // MAC (common on modern mobile OSes for privacy) or a
                                // spoofed address used to evade tracking.
                                None => "Randomized / Spoofed",
                            };

                            // Devices with unrecognised OUIs are assigned a medium risk
                            // rating because randomised or spoofed MACs can be used to
                            // bypass MAC-based network access controls.
                            let risk = if vendor == "Randomized / Spoofed" {
                                "Medium"
                            } else {
                                "Low"
                            };

                            devices.push(Device {
                                ip: ip.to_string(),
                                mac: mac_str,
                                vendor: vendor.to_string(),
                                risk: risk.to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    print_table(&devices);

    // Hand the discovered IP set to the monitoring engine, which will capture
    // and analyse traffic to and from each of these hosts going forward.
    let mut ips = HashSet::new();
    for d in &devices {
        ips.insert(d.ip.clone());
    }

    monitor::start_monitor(&ips);
}

/// Prints a formatted table of discovered devices to stdout.
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
}

/// Parses the IEEE OUI flat-file database into a MAC-prefix → vendor name map.
///
/// The file is expected to follow the standard IEEE `oui.txt` format, where each
/// vendor entry contains a line with the token `(hex)` separating the OUI prefix
/// from the organisation name (e.g. `AA-BB-CC   (hex)   Some Vendor Inc.`).
/// Dashes in the OUI are converted to colons to match the format produced by
/// `MacAddr::to_string()` in the ARP reply handler above.
fn load_oui_db() -> HashMap<String, String> {
    let data = fs::read_to_string("oui.txt").expect("Missing oui.txt");
    let mut map = HashMap::new();

    for line in data.lines() {
        if line.contains("(hex)") {
            let parts: Vec<&str> = line.split("(hex)").collect();
            let oui = parts[0].trim().replace("-", ":");
            let vendor = parts[1].trim().to_string();
            map.insert(oui, vendor);
        }
    }

    map
}

/// Constructs and transmits a single ARP request frame on the given channel.
///
/// The request is sent as a broadcast (destination MAC `FF:FF:FF:FF:FF:FF`) so
/// that all hosts on the segment receive it. The target MAC is set to zero, which
/// is the conventional placeholder in an ARP request — the whole point of the
/// request is to *discover* the target's MAC from its IP address.
///
/// The 42-byte buffer layout is: 14 bytes Ethernet II header + 28 bytes ARP payload.
///
/// # Arguments
/// * `tx`        - Raw datalink sender for the active interface.
/// * `my_mac`    - Hardware address of the sending interface, used as the ARP sender.
/// * `my_ip`     - IPv4 address of the sending interface, used as the ARP sender protocol address.
/// * `target_ip` - IPv4 address being queried; the host at this address should reply with its MAC.
fn send_arp_request(
    tx: &mut Box<dyn datalink::DataLinkSender>,
    my_mac: MacAddr,
    my_ip: Ipv4Addr,
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
        // Target MAC is zeroed — the purpose of this request is to resolve it.
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(target_ip);
    }

    tx.send_to(&buffer, None);
}
