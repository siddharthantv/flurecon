use std::time::Duration;

/// Maximum time a TCP flow can remain idle before being evicted from the flow table.
///
/// 120 seconds covers the tail of most real-world TCP sessions, including those with
/// long-polling or infrequent keepalives, without holding state indefinitely for
/// connections that closed without a FIN or RST being observed by the monitor.
pub const FLOW_TIMEOUT: Duration = Duration::from_secs(120);

/// Maximum time a host profile is retained after its last observed packet.
///
/// Shorter than [`FLOW_TIMEOUT`] because host-level anomaly detection (port scans,
/// SYN rates) is most meaningful over a recent window. A host that has been silent
/// for 60 seconds is unlikely to still be in an active scanning or attack phase,
/// and its profile can be discarded to reclaim memory.
pub const HOST_TIMEOUT: Duration = Duration::from_secs(60);

/// Sliding window over which distinct destination ports are counted for port scan detection.
///
/// SYN timestamps older than this value are evicted from `HostProfile::syn_times` before
/// each evaluation. 30 seconds is wide enough to catch methodical low-rate scanners
/// while remaining short enough to avoid false positives from legitimate burst traffic.
pub const PORT_SCAN_WINDOW: Duration = Duration::from_secs(30);

/// Observation window used to compute the instantaneous SYN rate for DoS detection.
///
/// Kept deliberately short (5 seconds) so that the rate calculation reflects current
/// burst behaviour rather than a diluted average over a longer period. A SYN flood
/// is characterised by sustained high rates, so a tight window catches the attack
/// quickly while still allowing brief legitimate bursts to pass undetected.
pub const DOS_WINDOW: Duration = Duration::from_secs(5);

/// RTT threshold above which a TCP handshake is flagged as abnormally slow.
///
/// 500 ms is a conservative ceiling for LAN and typical WAN connections; handshakes
/// exceeding this value suggest severe path congestion, a geographically distant peer,
/// or a middlebox introducing artificial delay. Tune downward in low-latency environments
/// to surface issues earlier.
pub const SLOW_RTT: Duration = Duration::from_millis(500);