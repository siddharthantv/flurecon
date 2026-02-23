//! Core data structures shared across all monitor sub-modules.
//!
//! Additions in v0.2.0:
//! - [`SessionStats`]  — atomic counters for the shutdown summary.
//! - [`Thresholds`]    — runtime-configurable detection thresholds (replaces
//!                       the hard-coded literals that were in detection.rs).
//! - [`ShutdownFlag`]  — a type alias for the `Arc<AtomicBool>` used to signal
//!                       the monitor loop and eviction thread to stop.

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use std::time::Instant;

// ── Shutdown signal ──────────────────────────────────────────────────────────

/// Shared shutdown flag.
///
/// Set to `true` by the `ctrlc` handler in `main`. Both the monitor packet
/// loop and the eviction thread poll this flag and exit when it is set.
pub type ShutdownFlag = Arc<AtomicBool>;

// ── Session statistics ────────────────────────────────────────────────────────

/// Atomically-updated session counters, accumulated throughout a monitoring run.
///
/// All fields use relaxed atomic ordering — they are written from the monitor
/// thread and read once by the shutdown handler on the main thread, so strict
/// sequential consistency is not required.
pub struct SessionStats {
    /// Total raw packets processed by the monitor loop.
    pub packets_total: AtomicU64,
    /// Total alert events emitted (any severity).
    pub alerts_emitted: AtomicU64,
    /// High-watermark: maximum distinct hosts seen simultaneously.
    pub hosts_seen: AtomicU64,
    /// High-watermark: maximum distinct flows tracked simultaneously.
    pub flows_tracked: AtomicU64,
}

impl SessionStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            packets_total:  AtomicU64::new(0),
            alerts_emitted: AtomicU64::new(0),
            hosts_seen:     AtomicU64::new(0),
            flows_tracked:  AtomicU64::new(0),
        })
    }
}

/// Shared type alias for the session statistics.
pub type SharedStats = Arc<SessionStats>;

// ── Detection thresholds ──────────────────────────────────────────────────────

/// Runtime-configurable detection thresholds.
///
/// In v0.1.0 these values were hard-coded literals inside `detection.rs`.
/// They are now populated from CLI arguments in `main` and passed through to
/// every function that needs them, making it easy to tune without recompiling.
#[derive(Debug, Clone)]
pub struct Thresholds {
    /// Distinct destination ports within PORT_SCAN_WINDOW before alerting.
    pub port_scan: usize,
    /// SYN rate (packets/second within DOS_WINDOW) that triggers DoS detection.
    pub dos_syn_rate: f32,
    /// Half-open connection count that (combined with syn_rate) triggers DoS.
    pub dos_half_open: u32,
    /// Distinct internal targets before a lateral-movement alert fires.
    pub lateral: usize,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            port_scan:    15,
            dos_syn_rate: 20.0,
            dos_half_open: 10,
            lateral:      10,
        }
    }
}

// ── Flow key ─────────────────────────────────────────────────────────────────

/// Uniquely identifies a bidirectional TCP flow between two endpoints.
///
/// Always normalised so the lexicographically smaller IP occupies `a_*`,
/// ensuring both directions of a connection map to the same entry.
#[derive(Hash, Eq, PartialEq, Debug)]
pub struct FlowKey {
    pub a_ip:   String,
    pub a_port: u16,
    pub b_ip:   String,
    pub b_port: u16,
}

// ── TCP state machine ─────────────────────────────────────────────────────────

/// Observed lifecycle state of a TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// SYN seen; handshake not yet complete.
    Syn,
    /// SYN-ACK seen; waiting for the final ACK.
    SynAck,
    /// Three-way handshake complete; data transfer may occur.
    Established,
    /// FIN seen; graceful teardown in progress.
    Fin,
    /// RST seen; connection aborted unconditionally.
    Reset,
}

// ── Per-flow tracking state ───────────────────────────────────────────────────

/// Per-connection tracking state for an active TCP flow.
pub struct TcpFlow {
    pub state:       TcpState,
    pub syn_time:    Instant,
    pub last_seq:    u32,
    pub last_ack:    u32,
    pub last_window: u16,
    pub dup_ack:     u32,
    pub retransmits: u32,
    pub last_seen:   Instant,
}

// ── Per-host behavioural profile ──────────────────────────────────────────────

/// Aggregated behavioural data for a single observed source IP.
pub struct HostProfile {
    /// Sliding window of SYN timestamps for SYN-rate computation.
    pub syn_times:   VecDeque<Instant>,
    /// Distinct destination ports contacted within the observation window.
    pub ports:       HashSet<u16>,
    /// Distinct internal IPs contacted; used for lateral-movement detection.
    pub targets:     HashSet<String>,
    /// Unique DNS names queried; logged on first observation.
    pub dns_queries: HashSet<String>,
    /// Unique TLS SNI hostnames observed in ClientHello messages.
    pub tls_sni:     HashSet<String>,
    /// SYNs without a completing ACK (potential flood signal).
    pub half_open:   u32,
    /// Cumulative RST packets attributed to this host.
    pub rst_count:   u32,
    /// Total packets processed for this host.
    pub packet_count: u64,
    /// Timestamp of the most recent packet; drives HOST_TIMEOUT eviction.
    pub last_seen:   Instant,
}
