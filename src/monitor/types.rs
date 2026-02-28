//! Core data structures shared across all monitor sub-modules.
//!
//! This module defines the fundamental types used for network monitoring,
//! including session statistics, detection thresholds, flow tracking, and
//! per-host behavioral profiles. These structures are designed to support
//! real-time anomaly detection across multiple threat vectors including
//! port scanning, DoS attacks, and lateral movement within networks.

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use std::time::Instant;

// ── Shutdown signal ──────────────────────────────────────────────────────────

/// Shared shutdown flag used to gracefully terminate the monitor loop.
///
/// This atomic boolean is checked periodically by the main monitoring thread
/// to allow clean shutdown without forceful termination.
pub type ShutdownFlag = Arc<AtomicBool>;

// ── Alert cooldown ────────────────────────────────────────────────────────────

/// Minimum time between repeated alerts of the same type for the same host.
///
/// Without a cooldown, any threshold that has been crossed fires an alert on
/// every subsequent packet, producing thousands of duplicate log lines per
/// second and inflating `alerts_emitted` meaninglessly. This constant ensures
/// each alert type fires at most once per host within this duration.
pub const ALERT_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(30);

// ── Session statistics ────────────────────────────────────────────────────────

/// Atomically-updated session counters accumulated throughout a monitoring run.
///
/// These statistics provide high-level visibility into monitor performance and
/// threat detection activity. All counters are thread-safe and updated without
/// locks using atomic operations.
pub struct SessionStats {
    /// Total raw packets processed by the monitor loop since startup.
    pub packets_total: AtomicU64,
    /// Total alert events emitted to the alerts system (any severity level).
    pub alerts_emitted: AtomicU64,
    /// Running total of distinct hosts ever seen (incremented on first discovery).
    pub total_hosts_seen: AtomicU64,
    /// Running total of distinct flows ever tracked (incremented on flow creation).
    pub total_flows_tracked: AtomicU64,
}

impl SessionStats {
    /// Creates a new session statistics tracker wrapped in an `Arc` for shared ownership.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            packets_total:       AtomicU64::new(0),
            alerts_emitted:      AtomicU64::new(0),
            total_hosts_seen:    AtomicU64::new(0),
            total_flows_tracked: AtomicU64::new(0),
        })
    }
}

/// Shared type alias for thread-safe access to session statistics.
pub type SharedStats = Arc<SessionStats>;

// ── Detection thresholds ──────────────────────────────────────────────────────

/// Configurable sensitivity thresholds for various anomaly detection algorithms.
///
/// These thresholds control when alerts are triggered for different threat
/// categories. Lower values produce more sensitive detection but increase
/// false-positive rates.
#[derive(Debug, Clone)]
pub struct Thresholds {
    /// Maximum number of distinct destination ports before triggering a port-scan alert.
    pub port_scan: usize,
    /// Maximum number of SYN packets per second before triggering a DoS alert.
    pub dos_syn_rate: f32,
    /// Maximum number of half-open connections before triggering a DoS alert.
    pub dos_half_open: u32,
    /// Maximum number of distinct internal targets before triggering a lateral-movement alert.
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

/// Unique identifier for a network flow using bidirectional socket information.
///
/// A flow is identified by two endpoints (IP, port) pairs and is used as a key
/// in hash maps to track TCP connections and their state machines.
#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct FlowKey {
    pub a_ip:   String,
    pub a_port: u16,
    pub b_ip:   String,
    pub b_port: u16,
}

// ── TCP state machine ─────────────────────────────────────────────────────────

/// TCP connection state for tracking during the Three-Way Handshake and beyond.
///
/// Used to reconstruct connection lifecycle for anomaly correlation and to
/// identify suspicious patterns like repeated half-open connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// SYN packet received (connection initiating).
    Syn,
    /// SYN-ACK packet received (peer responding).
    SynAck,
    /// Data exchange phase (fully established).
    Established,
    /// FIN packet received (graceful close initiated).
    Fin,
    /// RST packet received (abrupt termination).
    Reset,
}

// ── Per-flow tracking state ───────────────────────────────────────────────────

/// Per-connection TCP state and sequence tracking for a single flow.
///
/// Maintains the state machine progression and TCP feedback metrics
/// (sequence numbers, window size, duplicate ACKs) to detect retransmissions,
/// out-of-order delivery, and other transport-layer anomalies.
pub struct TcpFlow {
    /// Current state of the connection in the TCP state machine.
    pub state:       TcpState,
    /// Timestamp when the SYN packet for this flow was first observed.
    pub syn_time:    Instant,
    /// Last seen sequence number from the initiator.
    pub last_seq:    u32,
    /// Last seen acknowledgment number from the peer.
    pub last_ack:    u32,
    /// Last advertised TCP receive window size.
    pub last_window: u16,
    /// Count of duplicate ACKs received (indicates packet loss or reordering).
    pub dup_ack:     u32,
    /// Count of retransmitted segments detected.
    pub retransmits: u32,
    /// Most recent packet timestamp for this flow (used for flow timeout detection).
    pub last_seen:   Instant,
}

// ── Per-host behavioural profile ──────────────────────────────────────────────

/// Aggregated behavioral profile for a single observed source IP.
///
/// This structure accumulates traffic patterns, connection attempts, and
/// temporal metadata on a per-host basis. The profile is used to correlate
/// multiple packets into higher-level threat signals (port scanning, DoS
/// attacks, lateral movement, etc.).
pub struct HostProfile {
    /// Sliding window of SYN timestamps bounded to `PORT_SCAN_WINDOW` (30 s).
    ///
    /// Used to maintain the port-scan alert window. Older SYN times are
    /// discarded after 30 seconds to prevent indefinite memory growth.
    pub syn_times: VecDeque<Instant>,

    /// Sliding window of SYN timestamps bounded to `DOS_WINDOW` (5 s).
    ///
    /// Kept separate from `syn_times` so the DoS SYN-rate denominator uses
    /// the correct 5-second window. Previously both windows used `syn_times`
    /// bounded to 30 s while the rate was divided by 5 s, inflating the
    /// computed rate by 6×. This corrects that issue.
    pub dos_syn_times: VecDeque<Instant>,

    /// Destination ports contacted within the current port-scan window.
    ///
    /// Cleared when the window is reset after a port-scan alert fires (or when
    /// all SYN timestamps age out of `syn_times`), so it does not grow forever.
    /// Each unique port increments the port-scan counter.
    pub ports: HashSet<u16>,

    /// Distinct internal IPs contacted; used for lateral-movement detection.
    ///
    /// Cleared after a lateral-movement alert fires so that the alert cannot
    /// re-fire on every subsequent packet once the threshold is crossed.
    pub targets: HashSet<String>,

    /// Domain names queried via DNS from this host.
    pub dns_queries: HashSet<String>,
    /// TLS SNI hostnames for which this host initiated encrypted connections.
    pub tls_sni: HashSet<String>,
    /// Count of half-open connections (SYN without completion).
    pub half_open: u32,
    /// Count of reset packets sent by or to this host.
    pub rst_count: u32,
    /// Total packet count from this host (used for traffic volume assessment).
    pub packet_count: u64,
    /// Most recent packet timestamp from this host.
    pub last_seen: Instant,

    // ── Per-alert cooldown timestamps ─────────────────────────────────────────
    // Each field records the last time a specific alert type was emitted for
    // this host. `None` indicates the alert has never fired. The anomaly
    // detector skips re-alerting until at least `ALERT_COOLDOWN` has elapsed,
    // preventing alert spam while allowing re-alerts after sufficient time.

    /// Last time a port-scan alert was emitted for this host.
    pub last_alert_port_scan: Option<Instant>,
    /// Last time a DoS alert was emitted for this host.
    pub last_alert_dos: Option<Instant>,
    /// Last time a lateral-movement alert was emitted for this host.
    pub last_alert_lateral: Option<Instant>,
}

impl HostProfile {
    /// Creates a new behavioral profile for a newly discovered host.
    ///
    /// Initializes all collections as empty and sets the discovery timestamp
    /// to the provided `now` value. Alert cooldown timers start as `None`.
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
        }
    }
}