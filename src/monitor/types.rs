use std::collections::{HashSet, VecDeque};
use std::time::Instant;

/// Uniquely identifies a bidirectional TCP flow between two endpoints.
///
/// The key is always normalised so that the lexicographically smaller IP occupies
/// the `a_*` slots, ensuring that packets from both directions of a connection
/// map to the same entry in the flow table regardless of which side sent them.
#[derive(Hash, Eq, PartialEq, Debug)]
pub struct FlowKey {
    pub a_ip: String,
    pub a_port: u16,
    pub b_ip: String,
    pub b_port: u16,
}

/// Lifecycle state of a TCP connection as observed from packet headers.
///
/// Transitions follow the standard TCP handshake and teardown sequence.
/// Note that because the monitor is passive (not an endpoint), it may miss
/// the opening handshake of pre-existing connections and can only infer state
/// from whichever packets it happens to observe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// A SYN has been seen; the three-way handshake has not yet completed.
    Syn,
    /// A SYN-ACK has been seen; waiting for the final ACK from the initiator.
    SynAck,
    /// The three-way handshake is complete; data transfer may now occur.
    Established,
    /// A FIN has been observed; at least one side is initiating a graceful close.
    Fin,
    /// A RST was received; the connection was aborted unconditionally.
    Reset,
}

/// Per-flow tracking state for an active TCP connection.
///
/// Maintained for the lifetime of a flow and updated on every packet.
/// Fields are used both to drive the state machine in [`TcpState`] and to
/// detect transport-layer anomalies such as retransmissions and duplicate ACKs.
pub struct TcpFlow {
    /// Current position in the TCP connection lifecycle.
    pub state: TcpState,

    /// Timestamp of the initial SYN, used to compute handshake RTT when the
    /// SYN-ACK arrives. Stale values here indicate incomplete or dropped flows.
    pub syn_time: Instant,

    /// Sequence number from the most recently processed packet. A repeated value
    /// on the next packet in the same direction signals a retransmission.
    pub last_seq: u32,

    /// Acknowledgment number from the most recent packet. Consecutive packets
    /// acknowledging the same offset (without advancement) indicate duplicate ACKs,
    /// which TCP uses as a signal for fast retransmit after three occurrences.
    pub last_ack: u32,

    /// Advertised receive window from the most recent packet. A value of zero means
    /// the receiver's buffer is full and the sender must pause, which can stall
    /// throughput significantly if sustained.
    pub last_window: u16,

    /// Running count of consecutive duplicate ACKs. Reset to zero whenever `last_ack`
    /// advances. Reaching three triggers a duplicate-ACK alert.
    pub dup_ack: u32,

    /// Cumulative count of retransmitted segments detected for this flow, used as
    /// a signal of packet loss or severe congestion on the path.
    pub retransmits: u32,

    /// Timestamp of the most recent packet in either direction, used to identify
    /// idle flows that are candidates for eviction from the flow table.
    pub last_seen: Instant,
}

/// Aggregated behavioural profile for a single observed host.
///
/// Built up incrementally as packets are processed and consumed by the anomaly
/// detection layer to identify reconnaissance, denial-of-service, and lateral
/// movement patterns. One profile is maintained per unique source IP.
pub struct HostProfile {
    /// Sliding window of SYN timestamps used to compute instantaneous SYN rate.
    /// Entries older than [`DOS_WINDOW`] are evicted before each rate calculation.
    pub syn_times: VecDeque<Instant>,

    /// Distinct destination ports contacted by this host within the observation
    /// window. A large cardinality here is the primary indicator of a port scan.
    pub ports: HashSet<u16>,

    /// Distinct internal IP addresses contacted by this host. Used to detect
    /// lateral movement: an attacker pivoting through the network will typically
    /// reach a large number of internal hosts in a short time.
    pub targets: HashSet<String>,

    /// Unique DNS names queried by this host. Logged on first observation to
    /// provide visibility into domain lookups without flooding logs on repetition.
    pub dns_queries: HashSet<String>,

    /// Unique TLS SNI hostnames observed in ClientHello messages from this host.
    /// Available in plaintext before encryption, giving visibility into HTTPS
    /// destinations without decryption.
    pub tls_sni: HashSet<String>,

    /// Number of connections for which a SYN was seen but the handshake was never
    /// completed with a final ACK. A sustained high value is a strong indicator of
    /// a SYN flood or an aggressive scanning tool.
    pub half_open: u32,

    /// Cumulative count of RST packets attributed to this host. Elevated values
    /// can indicate port scanning, firewall rejections, or application-level errors.
    pub rst_count: u32,

    /// Total packets processed for this host across all flows and protocols.
    pub packet_count: u64,

    /// Timestamp of the most recent packet from this host, used to age out
    /// inactive profiles and reclaim memory from the host table.
    pub last_seen: Instant,
}