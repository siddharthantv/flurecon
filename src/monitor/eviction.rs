//! Background eviction task for the flow and host tables.
//!
//! This module implements a background thread that periodically removes stale
//! entries from the flow and host tracking tables. Entries are considered stale
//! if they haven't been updated within their respective timeout windows.
//!
//! ## Concurrency Strategy
//!
//! The tables use `DashMap` for fine-grained locking instead of a coarse-grained
//! `Arc<Mutex<HashMap>>`. This allows the monitor thread and eviction thread to
//! operate concurrently with minimal contention.
//!
//! ## Bug 4 fix — coarse `Mutex<HashMap>` replaced with `DashMap`
//!
//! Previously both tables were wrapped in `Arc<Mutex<HashMap<_,_>>>`. The
//! monitor thread held both locks for the entire duration of every packet,
//! and the eviction thread contended for the same locks. Under high packet
//! rates this caused measurable latency on the hot path.
//!
//! `DashMap` shards its internal map across multiple `RwLock`-protected
//! buckets, so concurrent readers and the eviction thread can make progress
//! without blocking each other on a single global lock.

use crate::monitor::config::{FLOW_TIMEOUT, HOST_TIMEOUT};
use crate::monitor::types::{FlowKey, HostProfile, ShutdownFlag, TcpFlow};
use dashmap::DashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// ── Shared table types ────────────────────────────────────────────────────────

/// Shared, sharded flow table. No external `Mutex` needed.
pub type SharedFlows = Arc<DashMap<FlowKey, TcpFlow>>;

/// Shared, sharded host table. No external `Mutex` needed.
pub type SharedHosts = Arc<DashMap<String, HostProfile>>;

// ── Eviction thread ───────────────────────────────────────────────────────────

/// Spawns the background eviction thread.
///
/// This thread wakes every `interval` seconds to perform housekeeping on the
/// flow and host tables. It removes entries that have exceeded their idle timeout
/// thresholds, freeing up memory and preventing stale state accumulation.
///
/// The thread monitors the `shutdown` flag and performs a final eviction pass
/// before exiting cleanly.
///
/// # Arguments
///
/// * `flows` - Reference to the shared flow table
/// * `hosts` - Reference to the shared host table
/// * `interval` - Sleep duration in seconds between eviction passes
/// * `shutdown` - Atomic flag signaling graceful shutdown
pub fn spawn_eviction_thread(
    flows:    SharedFlows,
    hosts:    SharedHosts,
    interval: u64,
    shutdown: ShutdownFlag,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let sleep_dur = Duration::from_secs(interval);

        loop {
            let mut slept = Duration::ZERO;
            // Sleep in 1-second intervals to remain responsive to shutdown signals
            while slept < sleep_dur {
                if shutdown.load(Ordering::Relaxed) {
                    evict(&flows, &hosts);
                    return;
                }
                thread::sleep(Duration::from_secs(1));
                slept += Duration::from_secs(1);
            }

            evict(&flows, &hosts);
        }
    })
}

/// Removes idle entries from both shared tables.
///
/// Uses `DashMap::retain` to iterate and filter entries. Unlike a global lock,
/// `retain` acquires per-shard write locks sequentially, allowing the monitor
/// thread to continue processing packets in uncontended shards concurrently
/// with eviction.
///
/// An entry is retained if its `last_seen` timestamp is within the configured
/// timeout window for its respective table type.
fn evict(flows: &SharedFlows, hosts: &SharedHosts) {
    flows.retain(|_, flow| flow.last_seen.elapsed() < FLOW_TIMEOUT);
    hosts.retain(|_, host| host.last_seen.elapsed() < HOST_TIMEOUT);
}