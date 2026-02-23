//! Structured logging for flurecon.
//!
//! Provides a [`Logger`] that writes events to stdout and optionally to a log
//! file. Output can be formatted as human-readable plain text or as
//! newline-delimited JSON (NDJSON), making it easy to ingest into log
//! shippers and SIEM platforms.
//!
//! All public functions are intentionally cheap — they take a shared reference
//! to the logger and do a single allocation per event for the formatted string.

use chrono::Local;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::sync::{Arc, Mutex};

// ── Event types ──────────────────────────────────────────────────────────────

/// All distinct event kinds that flurecon can emit.
///
/// Each variant carries exactly the fields needed to describe that event.
/// The `#[serde(tag = "event")]` attribute ensures JSON output includes an
/// `"event"` key so consumers can filter by type without inspecting structure.
#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event<'a> {
    /// Informational startup / status message.
    Info { message: &'a str },

    /// A host was discovered via ARP during the initial sweep.
    HostDiscovered {
        ip:     &'a str,
        mac:    &'a str,
        vendor: &'a str,
        risk:   &'a str,
    },

    /// A DNS query was observed for a previously unseen domain.
    Dns { src: &'a str, domain: &'a str },

    /// A TLS SNI hostname was extracted from a ClientHello.
    TlsSni { src: &'a str, sni: &'a str },

    /// A host exceeded the port-scan detection threshold.
    PortScan { src: &'a str, port_count: usize },

    /// A host exceeded both the SYN-rate and half-open thresholds.
    Dos {
        src:       &'a str,
        syn_rate:  f32,
        half_open: u32,
    },

    /// A host has contacted an unusually large number of internal targets.
    LateralMovement { src: &'a str, target_count: usize },

    /// A TCP handshake RTT exceeded the configured slow-RTT threshold.
    SlowHandshake { src: &'a str, rtt_ms: u128 },

    /// Three or more consecutive duplicate ACKs were observed on a flow.
    DupAck { src: &'a str, ack: u32 },

    /// The TCP receive window dropped to zero.
    ZeroWindow { src: &'a str, port: u16 },

    /// Session summary emitted on graceful shutdown.
    SessionSummary {
        duration_secs:   u64,
        hosts_seen:      usize,
        flows_tracked:   usize,
        packets_total:   u64,
        alerts_emitted:  u64,
    },
}

// ── Logger ───────────────────────────────────────────────────────────────────

/// Shared, thread-safe structured logger.
///
/// Constructed once in `main` and passed as an `Arc<Logger>` to every module
/// that needs to emit events. The internal `Mutex` serialises writes so that
/// output lines are never interleaved across threads.
pub struct Logger {
    /// Whether to format events as NDJSON instead of plain text.
    json:   bool,
    /// Optional buffered file writer. `None` when `--log-file` was not given.
    file:   Option<Mutex<BufWriter<std::fs::File>>>,
}

/// Type alias used throughout the codebase for convenience.
pub type SharedLogger = Arc<Logger>;

impl Logger {
    /// Creates a new logger.
    ///
    /// # Arguments
    /// * `json`     - Emit NDJSON instead of plain text when `true`.
    /// * `log_path` - If `Some`, open (or create) this file for appended writes.
    ///
    /// # Errors
    /// Returns an `io::Error` if the log file cannot be opened or created.
    pub fn new(json: bool, log_path: Option<&str>) -> io::Result<Self> {
        let file = match log_path {
            Some(path) => {
                let f = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?;
                Some(Mutex::new(BufWriter::new(f)))
            }
            None => None,
        };

        Ok(Self { json, file })
    }

    /// Logs a single [`Event`], writing to stdout and optionally to the log file.
    ///
    /// Plain-text output is prefixed with a timestamp and the event tag.
    /// NDJSON output is a single JSON object per line with a `"timestamp"` field
    /// injected alongside the event fields.
    pub fn log(&self, event: &Event) {
        let timestamp = Local::now().format("%Y-%m-%dT%H:%M:%S%.3f").to_string();

        let line = if self.json {
            // Serialise the event to a JSON Value so we can inject the timestamp.
            let mut val = serde_json::to_value(event).unwrap_or_default();
            if let Some(obj) = val.as_object_mut() {
                obj.insert(
                    "timestamp".to_string(),
                    serde_json::Value::String(timestamp.clone()),
                );
            }
            serde_json::to_string(&val).unwrap_or_default()
        } else {
            // Plain-text: "[TIMESTAMP] [TAG] human-readable description"
            format!("[{}] {}", timestamp, self.plain_text(event))
        };

        // Always write to stdout.
        println!("{}", line);

        // If a log file was configured, also write there.
        if let Some(mutex) = &self.file {
            if let Ok(mut writer) = mutex.lock() {
                let _ = writeln!(writer, "{}", line);
                let _ = writer.flush();
            }
        }
    }

    /// Formats an [`Event`] as a human-readable plain-text string (no timestamp).
    fn plain_text(&self, event: &Event) -> String {
        match event {
            Event::Info { message } =>
                format!("[INFO] {}", message),

            Event::HostDiscovered { ip, mac, vendor, risk } =>
                format!("[HOST] {} | {} | {} | Risk: {}", ip, mac, vendor, risk),

            Event::Dns { src, domain } =>
                format!("[DNS] {} queried {}", src, domain),

            Event::TlsSni { src, sni } =>
                format!("[TLS SNI] {} → {}", src, sni),

            Event::PortScan { src, port_count } =>
                format!("[PORT SCAN] {} scanned {} ports", src, port_count),

            Event::Dos { src, syn_rate, half_open } =>
                format!("[DoS] {} SYN rate {:.1}/s half-open {}", src, syn_rate, half_open),

            Event::LateralMovement { src, target_count } =>
                format!("[LATERAL MOVEMENT] {} contacted {} internal hosts", src, target_count),

            Event::SlowHandshake { src, rtt_ms } =>
                format!("[SLOW HANDSHAKE] {} RTT={}ms", src, rtt_ms),

            Event::DupAck { src, ack } =>
                format!("[DUP ACK] {} ack={}", src, ack),

            Event::ZeroWindow { src, port } =>
                format!("[ZERO WINDOW] {}:{}", src, port),

            Event::SessionSummary {
                duration_secs, hosts_seen, flows_tracked, packets_total, alerts_emitted
            } => format!(
                "[SUMMARY] duration={}s hosts={} flows={} packets={} alerts={}",
                duration_secs, hosts_seen, flows_tracked, packets_total, alerts_emitted
            ),
        }
    }
}
