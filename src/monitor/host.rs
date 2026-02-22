use crate::monitor::types::HostProfile;
use std::collections::{HashSet, VecDeque};
use std::time::Instant;

impl HostProfile {
    /// Creates a new [`HostProfile`] with empty collections and zeroed counters.
    ///
    /// `now` is recorded as the initial `last_seen` timestamp so that age-based
    /// eviction logic has a valid baseline from the moment the host is first observed.
    pub fn new(now: Instant) -> Self {
        Self {
            syn_times: VecDeque::new(),
            ports: HashSet::new(),
            targets: HashSet::new(),
            dns_queries: HashSet::new(),
            tls_sni: HashSet::new(),
            half_open: 0,
            rst_count: 0,
            packet_count: 0,
            last_seen: now,
        }
    }

    /// Updates the core per-packet metrics for this host.
    ///
    /// Should be called once for every packet attributed to this host, regardless of
    /// protocol. Tracks the destination in the `targets` set (used later for lateral
    /// movement detection) and refreshes `last_seen` so idle hosts can be expired
    /// from the flow table.
    pub fn update_basic(&mut self, dst: &String, now: Instant) {
        self.packet_count += 1;
        // `targets` is a HashSet, so duplicate destinations are deduplicated automatically;
        // its length serves as a distinct-host-contact counter for anomaly detection.
        self.targets.insert(dst.clone());
        self.last_seen = now;
    }

    /// Records a DNS query and logs the domain if it has not been seen before.
    ///
    /// Deduplication via the `dns_queries` set ensures each domain is logged exactly
    /// once per host, preventing log flooding on hosts that repeatedly resolve the
    /// same names (e.g., keep-alive checks or CDN polling).
    pub fn handle_dns(&mut self, src: &str, domain: String) {
        // `HashSet::insert` returns `true` only when the value was not already present,
        // so the log line fires exclusively on the first observation of each domain.
        if self.dns_queries.insert(domain.clone()) {
            println!("[DNS] {} queried {}", src, domain);
        }
    }

    /// Records a TLS SNI hostname and logs it if it has not been seen before.
    ///
    /// SNI values are sent in plaintext during the TLS handshake, making them
    /// available for inspection without decryption. Deduplication ensures that
    /// long-lived connections or repeated handshakes (e.g., HTTP/2 session resumption)
    /// do not produce redundant log entries.
    pub fn handle_tls(&mut self, src: &str, sni: String) {
        // Same insert-and-check idiom as `handle_dns`: log once per unique hostname.
        if self.tls_sni.insert(sni.clone()) {
            println!("[TLS SNI] {} → {}", src, sni);
        }
    }
}