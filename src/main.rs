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

struct Device {
    ip: String,
    mac: String,
    vendor: String,
    risk: String,
}

fn main() {
    println!("[+] Loading OUI database...");
    let oui_db = load_oui_db();
    println!("[+] Loaded {} vendors", oui_db.len());

    // --- Find interface & IP ---
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

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|i| i.name == iface_name)
        .expect("Interface not found");

    let my_mac = interface.mac.unwrap();
    println!("My MAC: {}", my_mac);

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        _ => panic!("Failed to open datalink channel"),
    };

    println!("Scanning LAN...");

    // ARP scan /24
    for i in 1..=254 {
        let target_ip = Ipv4Addr::new(
            my_ip.octets()[0],
            my_ip.octets()[1],
            my_ip.octets()[2],
            i,
        );
        send_arp_request(&mut tx, my_mac, my_ip, target_ip);
    }

    let mut devices: Vec<Device> = Vec::new();
    let start = Instant::now();

    while start.elapsed() < Duration::from_secs(3) {
        if let Ok(packet) = rx.next() {
            if let Some(eth) = EthernetPacket::new(packet) {
                if eth.get_ethertype() == EtherTypes::Arp {
                    if let Some(arp) = ArpPacket::new(eth.payload()) {
                        if arp.get_operation() == ArpOperations::Reply {
                            let ip = arp.get_sender_proto_addr();
                            if ip == my_ip {
                                continue;
                            }

                            let mac = arp.get_sender_hw_addr();
                            let mac_str = mac.to_string().to_uppercase();
                            let oui = &mac_str[0..8];

                            let vendor = match oui_db.get(oui) {
                                Some(v) => v.as_str(),
                                None => "Randomized / Spoofed",
                            };

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

    let mut ips = HashSet::new();
    for d in &devices {
        ips.insert(d.ip.clone());
    }

    monitor::start_monitor(&ips);
}

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
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(target_ip);
    }

    tx.send_to(&buffer, None);
}

