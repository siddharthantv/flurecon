//! [`HostProfile`] constructor and per-packet update methods.

use crate::logger::{Event, SharedLogger};
use crate::monitor::types::HostProfile;
use std::collections::{HashSet, VecDeque};
use std::time::Instant;

impl HostProfile {
    /// Creates a new [`HostProfile`] with empty collections and zeroed counters.
    pub fn new(now: Instant) -> Self {
        Self {
            syn_times:    VecDeque::new(),
            ports:        HashSet::new(),
            targets:      HashSet::new(),
            dns_queries:  HashSet::new(),
            tls_sni:      HashSet::new(),
            half_open:    0,
            rst_count:    0,
            packet_count: 0,
            last_seen:    now,
        }
    }

    /// Increments the packet counter, records the destination contact, and
    /// refreshes `last_seen`. Call once per packet regardless of protocol.
    pub fn update_basic(&mut self, dst: &String, now: Instant) {
        self.packet_count += 1;
        self.targets.insert(dst.clone());
        self.last_seen = now;
    }

    /// Records a DNS query; logs to the structured logger on first observation only.
    pub fn handle_dns(&mut self, src: &str, domain: String, logger: &SharedLogger) {
        if self.dns_queries.insert(domain.clone()) {
            logger.log(&Event::Dns { src, domain: &domain });
        }
    }

    /// Records a TLS SNI hostname; logs on first observation only.
    pub fn handle_tls(&mut self, src: &str, sni: String, logger: &SharedLogger) {
        if self.tls_sni.insert(sni.clone()) {
            logger.log(&Event::TlsSni { src, sni: &sni });
        }
    }
}
