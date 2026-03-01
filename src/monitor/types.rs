//! Core data structures shared across all monitor sub-modules.
//!
//! This module defines the fundamental types used for session tracking, threat
//! detection thresholds, TCP flow state management, and per-host behavioral
//! profiling. All structures are designed to be thread-safe and efficiently
//! shared across monitor sub-modules via `Arc` pointers.
//!
//! # Changes in this patch:
//! - [`HostProfile`] gains `dos_syn_times` — a second SYN deque bounded to
//!   `DOS_WINDOW` so the DoS rate is computed over the correct 5-second window
//!   instead of the 30-second port-scan window.
//! - [`HostProfile`] gains per-alert `last_alert_*` `Option<Instant>` fields
//!   that drive a per-host, per-alert-type cooldown so each alert fires at
//!   most once per `ALERT_COOLDOWN` rather than on every packet.
//! - [`SessionStats`] fields renamed to `total_hosts_seen` / `total_flows_tracked`
//!   to make clear they are running totals, not high-watermarks.
//! - [`ShutdownFlag`] type alias unchanged.
//! - [`Thresholds`] unchanged.

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use std::time::Instant;

// ── Shutdown signal ──────────────────────────────────────────────────────────

/// Shared shutdown flag used to signal graceful termination across all threads.
///
/// When set to `true`, all monitor threads should cease processing and exit
/// their event loops.
pub type ShutdownFlag = Arc<AtomicBool>;

// ── Alert cooldown ────────────────────────────────────────────────────────────

/// Minimum time between repeated alerts of the same type for the same host.
///
/// Without a cooldown, any threshold that has been crossed fires an alert on
/// every subsequent packet, producing thousands of duplicate log lines per
/// second and inflating `alerts_emitted` meaninglessly.
pub const ALERT_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(30);

// ── Session statistics ────────────────────────────────────────────────────────

/// Atomically-updated session counters accumulated throughout a monitoring run.
///
/// These counters provide high-level visibility into monitor activity without
/// requiring locks. All fields use `AtomicU64` for lock-free concurrent updates.
pub struct SessionStats {
    /// Total raw packets processed by the monitor loop.
    pub packets_total: AtomicU64,
    /// Total alert events emitted (any severity).
    pub alerts_emitted: AtomicU64,
    /// Running total of distinct hosts ever seen (incremented on first sight).
    pub total_hosts_seen: AtomicU64,
    /// Running total of distinct flows ever tracked (incremented on creation).
    pub total_flows_tracked: AtomicU64,
}

impl SessionStats {
    /// Constructs a new [`SessionStats`] with all counters initialized to zero.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            packets_total:       AtomicU64::new(0),
            alerts_emitted:      AtomicU64::new(0),
            total_hosts_seen:    AtomicU64::new(0),
            total_flows_tracked: AtomicU64::new(0),
        })
    }
}

/// Shared type alias for the session statistics.
pub type SharedStats = Arc<SessionStats>;

// ── Detection thresholds ──────────────────────────────────────────────────────

/// Detection thresholds for various threat types.
///
/// These values determine when anomalies cross from normal behavior into
/// suspicious territory and trigger alerts.
#[derive(Debug, Clone)]
pub struct Thresholds {
    /// Maximum number of distinct destination ports before a port-scan alert fires.
    pub port_scan: usize,
    /// Maximum SYN rate (packets/second) over the 5-second window before a DoS alert fires.
    pub dos_syn_rate: f32,
    /// Maximum number of half-open connections before a half-open connection alert fires.
    pub dos_half_open: u32,
    /// Maximum number of distinct internal IPs contacted before a lateral-movement alert fires.
    pub lateral: usize,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            port_scan:     15,
            dos_syn_rate:  20.0,
            dos_half_open: 10,
            lateral:       10,
        }
    }
}

// ── Flow key ─────────────────────────────────────────────────────────────────

/// Unique identifier for a bidirectional TCP flow.
///
/// Identifies a connection by the two endpoints (IP:port pairs) regardless of
/// direction. Used as a key in flow tracking maps.
#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct FlowKey {
    pub a_ip:   String,
    pub a_port: u16,
    pub b_ip:   String,
    pub b_port: u16,
}

// ── TCP state machine ─────────────────────────────────────────────────────────

/// TCP connection state observed during packet processing.
///
/// Tracks the progression of a connection through its lifecycle, used to
/// identify suspicious patterns such as half-open connections or abnormal
/// termination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// SYN received from initiator.
    Syn,
    /// SYN-ACK received from responder.
    SynAck,
    /// Connection established (ACK received post-SYN-ACK).
    Established,
    /// FIN received (graceful termination).
    Fin,
    /// RST received (abrupt termination).
    Reset,
}

// ── Per-flow tracking state ───────────────────────────────────────────────────

/// Per-flow TCP connection state and metrics.
///
/// Maintains detailed packet-level information for a single flow to detect
/// anomalies such as retransmissions, duplicate ACKs, and zero-window conditions.
pub struct TcpFlow {
    /// Current state of the TCP connection state machine.
    pub state: TcpState,
    /// Timestamp when the SYN packet for this flow was first observed.
    pub syn_time: Instant,
    /// Last observed sequence number from the initiator.
    pub last_seq: u32,
    /// Last observed acknowledgment number from the responder.
    pub last_ack: u32,
    /// Last observed receive window size from the responder.
    pub last_window: u16,
    /// Count of duplicate ACKs received.
    pub dup_ack: u32,
    /// Count of detected retransmissions.
    pub retransmits: u32,
    /// Most recent timestamp this flow was active.
    pub last_seen: Instant,
}

// ── Per-host behavioural profile ──────────────────────────────────────────────

/// Aggregated behavioral data for a single observed source IP.
///
/// Tracks connection patterns, DNS/TLS activity, and alert history to detect
/// scanning, denial-of-service, and lateral-movement attacks from a single host.
pub struct HostProfile {
    /// Sliding window of SYN timestamps bounded to `PORT_SCAN_WINDOW` (30 s).
    /// Used only for port-scan window maintenance — NOT for DoS rate.
    pub syn_times: VecDeque<Instant>,

    /// Sliding window of SYN timestamps bounded to `DOS_WINDOW` (5 s).
    ///
    /// Kept separate from `syn_times` so the DoS SYN-rate denominator is the
    /// correct 5-second window. Previously `syn_times` was bounded to 30 s
    /// while the rate was divided by 5 s, inflating the computed rate 6×.
    pub dos_syn_times: VecDeque<Instant>,

    /// Destination ports contacted within the current port-scan window.
    ///
    /// Cleared when the window is reset after a port-scan alert fires (or when
    /// all SYN timestamps age out of `syn_times`), so it does not grow forever.
    pub ports: HashSet<u16>,

    /// Distinct internal IPs contacted; used for lateral-movement detection.
    ///
    /// Cleared after a lateral-movement alert fires so that the alert cannot
    /// re-fire on every subsequent packet once the threshold is crossed.
    pub targets: HashSet<String>,

    /// Domain names queried by this host.
    pub dns_queries: HashSet<String>,
    /// TLS SNI values presented by this host.
    pub tls_sni: HashSet<String>,
    /// Count of half-open TCP connections (SYN sent, no SYN-ACK received).
    pub half_open: u32,
    /// Count of TCP RST packets received.
    pub rst_count: u32,
    /// Total number of packets seen from this host.
    pub packet_count: u64,
    /// Most recent timestamp this host was active.
    pub last_seen: Instant,

    // ── Per-alert cooldown timestamps ─────────────────────────────────────────
    // Each field records when that alert type last fired for this host.
    // `None` means the alert has never fired. `detect_host_anomalies` skips
    // re-alerting until at least `ALERT_COOLDOWN` has elapsed.

    /// Timestamp of the last port-scan alert for this host.
    pub last_alert_port_scan: Option<Instant>,
    /// Timestamp of the last DoS alert for this host.
    pub last_alert_dos: Option<Instant>,
    /// Timestamp of the last lateral-movement alert for this host.
    pub last_alert_lateral: Option<Instant>,

    /// Destination ports for which a ZERO WINDOW alert has already fired from
    /// this source. Keyed on the destination port (the port being probed) so
    /// that one alert fires per unique port regardless of how many flows nmap
    /// or another scanner creates toward that port.
    pub zero_window_ports: HashSet<u16>,
}

impl HostProfile {
    /// Constructs a new [`HostProfile`] initialized to the given time.
    pub fn new(now: Instant) -> Self {
        Self {
            syn_times:     VecDeque::new(),
            dos_syn_times: VecDeque::new(),
            ports:         HashSet::new(),
            targets:       HashSet::new(),
            dns_queries:   HashSet::new(),
            tls_sni:       HashSet::new(),
            half_open:     0,
            rst_count:     0,
            packet_count:  0,
            last_seen:     now,

            last_alert_port_scan: None,
            last_alert_dos:       None,
            last_alert_lateral:   None,
            zero_window_ports:    HashSet::new(),
        }
    }
}