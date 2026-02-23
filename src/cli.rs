use clap::Parser;

/// flurecon — LAN reconnaissance and real-time traffic analysis engine.
///
/// Performs an ARP-based host discovery sweep on the local subnet, then
/// monitors traffic to and from discovered hosts for security anomalies.
#[derive(Parser, Debug, Clone)]
#[command(
    name    = "flurecon",
    version = "0.2.0",
    about   = "LAN reconnaissance and network traffic analysis engine",
    long_about = None,
)]
pub struct Cli {
    // ── Interface ────────────────────────────────────────────────────────────

    /// Network interface to use for scanning and capture.
    ///
    /// If omitted, flurecon selects the first non-loopback IPv4 interface
    /// automatically. Use `ip link` or `ifconfig` to list available interfaces.
    #[arg(short = 'i', long = "interface", value_name = "IFACE")]
    pub interface: Option<String>,

    // ── Logging ──────────────────────────────────────────────────────────────

    /// Write log output to this file in addition to stdout.
    ///
    /// The file is created if it does not exist and appended to if it does.
    /// JSON mode (--json) affects the format written to this file as well.
    #[arg(short = 'o', long = "log-file", value_name = "PATH")]
    pub log_file: Option<String>,

    /// Emit log entries as newline-delimited JSON (NDJSON).
    ///
    /// Each event is a self-contained JSON object on its own line, suitable
    /// for ingestion by log shippers (Logstash, Fluentd, Vector) or SIEM
    /// platforms (Splunk, Elastic, Loki).
    #[arg(short = 'j', long = "json")]
    pub json: bool,

    // ── ARP Scan ─────────────────────────────────────────────────────────────

    /// Seconds to wait for ARP replies after the sweep completes.
    ///
    /// Increase on slow or congested networks. Decrease for faster startup
    /// when the network is known to be responsive. Default: 3.
    #[arg(long = "arp-timeout", value_name = "SECS", default_value_t = 3)]
    pub arp_timeout: u64,

    // ── PCAP Replay ──────────────────────────────────────────────────────────

    /// Read packets from a saved PCAP file instead of a live interface.
    ///
    /// In replay mode the ARP scan phase is skipped; all unique source IPs
    /// found in the file are automatically treated as tracked hosts.
    /// Eviction timeouts still apply but the wall-clock timestamps come from
    /// packet metadata rather than Instant::now().
    #[arg(short = 'r', long = "read", value_name = "FILE")]
    pub pcap_file: Option<String>,

    // ── Detection Thresholds (overrides config.rs defaults) ──────────────────

    /// Minimum distinct ports within the scan window to trigger a PORT SCAN alert.
    #[arg(long = "port-scan-threshold", value_name = "N", default_value_t = 15)]
    pub port_scan_threshold: usize,

    /// SYN rate (per second) above which a DoS alert fires (combined with --dos-half-open).
    #[arg(long = "dos-syn-rate", value_name = "RATE", default_value_t = 20.0)]
    pub dos_syn_rate: f32,

    /// Half-open connection count above which a DoS alert fires (combined with --dos-syn-rate).
    #[arg(long = "dos-half-open", value_name = "N", default_value_t = 10)]
    pub dos_half_open: u32,

    /// Distinct internal hosts contacted before a LATERAL MOVEMENT alert fires.
    #[arg(long = "lateral-threshold", value_name = "N", default_value_t = 10)]
    pub lateral_threshold: usize,

    // ── Eviction ─────────────────────────────────────────────────────────────

    /// How often (in seconds) the background eviction task runs.
    ///
    /// Lower values free memory faster at the cost of slightly higher CPU
    /// overhead from the cleanup thread. Default: 10.
    #[arg(long = "evict-interval", value_name = "SECS", default_value_t = 10)]
    pub evict_interval: u64,
}
