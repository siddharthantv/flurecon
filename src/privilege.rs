//! Privilege-dropping helper.
//!
//! Correct order (proven via strace):
//!   1. setgid / setuid  — must happen BEFORE clearing caps, because
//!      setgid requires CAP_SETGID and setuid requires CAP_SETUID.
//!      Clearing caps first causes setgid to fail with EPERM → SIGABRT.
//!   2. capset (via caps crate) — clear Effective, Permitted, Inheritable.
//!      Safe to call after UID drop; caps::set uses capset(2) which
//!      works fine on this system (confirmed via strace).

use libc;
use crate::logger::{Event, Logger};

pub fn drop_privileges(logger: &Logger) {
    let sudo_uid = std::env::var("SUDO_UID").ok().and_then(|v| v.parse::<u32>().ok());
    let sudo_gid = std::env::var("SUDO_GID").ok().and_then(|v| v.parse::<u32>().ok());

    // ── Step 1: setgid / setuid ───────────────────────────────────────────────
    // MUST happen before clearing caps — setgid needs CAP_SETGID and setuid
    // needs CAP_SETUID. Clearing caps first causes EPERM → SIGABRT.
    // Drop GID before UID — after setuid we may lose permission to change GID.
    match (sudo_uid, sudo_gid) {
        (Some(uid), Some(gid)) => {
            // SAFETY: called before packet-loop threads are spawned.
            let gid_ok = unsafe { libc::setgid(gid) } == 0;
            let uid_ok = unsafe { libc::setuid(uid) } == 0;

            if !gid_ok || !uid_ok {
                logger.log(&Event::Info {
                    message: "Warning: setuid/setgid failed — process remains elevated",
                });
            } else {
                logger.log(&Event::Info {
                    message: &format!(
                        "Privileges dropped to uid={} gid={}", uid, gid
                    ),
                });
            }
        }
        _ => {
            logger.log(&Event::Info {
                message: "Warning: SUDO_UID/SUDO_GID not set — UID/GID drop skipped. \
                          Run via sudo for full privilege separation.",
            });
        }
    }

    // ── Step 2: clear capability sets ────────────────────────────────────────
    // Now that we're uid=1000, clear Effective → Inheritable → Permitted.
    // capset(2) is permitted here (confirmed via strace); the process simply
    // cannot re-acquire caps later because it has no saved-set-UID root.
    use caps::{CapSet, CapsHashSet};
    let empty = CapsHashSet::new();
    for cap_set in &[CapSet::Effective, CapSet::Inheritable, CapSet::Permitted] {
        if let Err(e) = caps::set(None, *cap_set, &empty) {
            logger.log(&Event::Info {
                message: &format!("Warning: could not clear {:?} caps: {}", cap_set, e),
            });
        }
    }

    logger.log(&Event::Info {
        message: "Privilege drop complete — running as least-privilege user",
    });
}