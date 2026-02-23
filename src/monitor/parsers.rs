//! Protocol parsers for DNS and TLS SNI. Unchanged from v0.1.0.

/// Parses a DNS query name from a raw DNS packet payload.
pub fn parse_dns_name(payload: &[u8]) -> Option<String> {
    if payload.len() < 12 { return None; }
    let mut idx = 12;
    let mut name = String::new();
    while idx < payload.len() {
        let len = payload[idx] as usize;
        if len == 0 || idx + len + 1 > payload.len() { break; }
        if !name.is_empty() { name.push('.'); }
        idx += 1;
        name.push_str(std::str::from_utf8(&payload[idx..idx + len]).ok()?);
        idx += len;
    }
    if name.is_empty() { None } else { Some(name) }
}

/// Extracts the TLS SNI hostname from a ClientHello record.
pub fn parse_tls_sni(payload: &[u8]) -> Option<String> {
    if payload.len() < 43 || payload[0] != 0x16 { return None; }
    let mut i = 43;
    while i + 9 < payload.len() {
        if payload[i] == 0x00 && payload[i + 1] == 0x00 {
            let len   = ((payload[i + 7] as usize) << 8) | payload[i + 8] as usize;
            let start = i + 9;
            if start + len <= payload.len() {
                return std::str::from_utf8(&payload[start..start + len])
                    .ok()
                    .map(|s| s.to_string());
            }
            break;
        }
        i += 1;
    }
    None
}
