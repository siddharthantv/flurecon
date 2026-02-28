//! [`HostProfile`] per-packet update methods.
//!
//! `HostProfile::new` is now defined in `types.rs` alongside the struct so
//! that the cooldown fields are initialised in one place.

use crate::logger::{Event, SharedLogger};
use crate::monitor::types::HostProfile;
use std::time::Instant;

impl HostProfile {
    /// Increments the packet counter, records the destination contact, and
    /// refreshes `last_seen`. Call once per packet regardless of protocol.
    ///
    /// # Arguments
    ///
    /// * `dst` - The destination address to record as a contact target
    /// * `now` - The current timestamp for updating the last seen time
    pub fn update_basic(&mut self, dst: &String, now: Instant) {
        self.packet_count += 1;
        self.targets.insert(dst.clone());
        self.last_seen = now;
    }

    /// Records a DNS query and logs the event to the structured logger.
    ///
    /// Only logs on first observation of a unique domain. Subsequent queries
    /// to the same domain are recorded but not logged to avoid log spam.
    ///
    /// # Arguments
    ///
    /// * `src` - The source address initiating the DNS query
    /// * `domain` - The domain name being queried
    /// * `logger` - Reference to the shared logger for event recording
    pub fn handle_dns(&mut self, src: &str, domain: String, logger: &SharedLogger) {
        if self.dns_queries.insert(domain.clone()) {
            logger.log(&Event::Dns { src, domain: &domain });
        }
    }

    /// Records a TLS SNI hostname and logs the event to the structured logger.
    ///
    /// Only logs on first observation of a unique SNI hostname. Subsequent
    /// connections using the same hostname are recorded but not logged.
    ///
    /// # Arguments
    ///
    /// * `src` - The source address initiating the TLS connection
    /// * `sni` - The Server Name Indication hostname
    /// * `logger` - Reference to the shared logger for event recording
    pub fn handle_tls(&mut self, src: &str, sni: String, logger: &SharedLogger) {
        if self.tls_sni.insert(sni.clone()) {
            logger.log(&Event::TlsSni { src, sni: &sni });
        }
    }
}