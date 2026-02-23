use std::time::Duration;
pub const FLOW_TIMEOUT:     Duration = Duration::from_secs(120);
pub const HOST_TIMEOUT:     Duration = Duration::from_secs(60);
pub const PORT_SCAN_WINDOW: Duration = Duration::from_secs(30);
pub const DOS_WINDOW:       Duration = Duration::from_secs(5);
pub const SLOW_RTT:         Duration = Duration::from_millis(500);
