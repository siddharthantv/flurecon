//! Background eviction task for the flow and host tables.
//!
//! In v0.1.0, `flows.retain()` and `hosts.retain()` were called inline on
//! every packet, which meant a full linear scan of both tables ran at line
//! rate. Under high packet volumes this added measurable latency to the hot
//! packet path.
//!
//! v0.2.0 moves eviction to a dedicated thread that wakes on a configurable
//! interval ([`Config::evict_interval`]) and performs the cleanup while the
//! monitor thread continues processing packets. The two threads share the
//! tables behind an `Arc<Mutex<_>>`, which is already necessary now that the
//! eviction thread needs access.

use crate::monitor::config::{FLOW_TIMEOUT, HOST_TIMEOUT};
use crate::monitor::types::{FlowKey, HostProfile, ShutdownFlag, TcpFlow};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Type aliases for the shared, mutex-protected state tables.
pub type SharedFlows = Arc<Mutex<HashMap<FlowKey, TcpFlow>>>;
pub type SharedHosts = Arc<Mutex<HashMap<String, HostProfile>>>;

/// Spawns the background eviction thread.
///
/// The thread wakes every `interval` seconds, locks each table in turn,
/// removes entries that have been idle longer than their configured timeout,
/// and goes back to sleep. It exits cleanly when `shutdown` is set to `true`.
///
/// # Arguments
/// * `flows`    - Shared flow table, also owned by the monitor loop.
/// * `hosts`    - Shared host table, also owned by the monitor loop.
/// * `interval` - How often (in seconds) to run the eviction sweep.
/// * `shutdown` - Shared flag; the thread exits when this is `true`.
///
/// # Returns
/// A [`thread::JoinHandle`] the caller can join on shutdown to ensure a final
/// eviction pass completes before the summary is printed.
pub fn spawn_eviction_thread(
    flows:    SharedFlows,
    hosts:    SharedHosts,
    interval: u64,
    shutdown: ShutdownFlag,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let sleep_dur = Duration::from_secs(interval);

        loop {
            // Sleep in 1-second increments so we can notice the shutdown flag
            // promptly rather than waiting out the full interval.
            let mut slept = Duration::ZERO;
            while slept < sleep_dur {
                if shutdown.load(Ordering::Relaxed) {
                    // Do one final eviction pass before exiting so that the
                    // summary printed by main reflects a clean state.
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
/// Each table is locked, scanned, and unlocked independently to minimise
/// contention with the monitor thread. Flows are checked against
/// [`FLOW_TIMEOUT`]; hosts against [`HOST_TIMEOUT`].
fn evict(flows: &SharedFlows, hosts: &SharedHosts) {
    if let Ok(mut f) = flows.lock() {
        f.retain(|_, flow| flow.last_seen.elapsed() < FLOW_TIMEOUT);
    }
    if let Ok(mut h) = hosts.lock() {
        h.retain(|_, host| host.last_seen.elapsed() < HOST_TIMEOUT);
    }
}
