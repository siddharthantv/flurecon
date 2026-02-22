/// Parses a DNS query name from a raw DNS packet payload.
///
/// DNS names are encoded as a sequence of length-prefixed labels (e.g., `\x03www\x07example\x03com\x00`),
/// which this function reassembles into a dot-separated string (e.g., `"www.example.com"`).
///
/// # Arguments
/// * `payload` - Raw bytes of the DNS packet, starting from the beginning of the DNS header.
///
/// # Returns
/// * `Some(String)` containing the parsed domain name on success.
/// * `None` if the payload is too short, malformed, or contains invalid UTF-8.
pub fn parse_dns_name(payload: &[u8]) -> Option<String> {
    // DNS headers are 12 bytes; the question section (where the name lives) starts immediately after.
    if payload.len() < 12 {
        return None;
    }

    // Begin reading past the 12-byte DNS header.
    let mut idx = 12;
    let mut name = String::new();

    while idx < payload.len() {
        // Each label is preceded by a single byte indicating its length.
        // A zero-length byte signals the end of the name.
        let len = payload[idx] as usize;
        if len == 0 || idx + len + 1 > payload.len() {
            break;
        }

        // Separate labels with a dot, mirroring standard domain name notation.
        if !name.is_empty() {
            name.push('.');
        }

        // Advance past the length byte and read `len` bytes as a UTF-8 label.
        idx += 1;
        name.push_str(std::str::from_utf8(&payload[idx..idx + len]).ok()?);
        idx += len;
    }

    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Extracts the Server Name Indication (SNI) hostname from a TLS ClientHello message.
///
/// SNI is a TLS extension (type `0x0000`) that allows a client to specify which hostname
/// it is attempting to connect to during the handshake. This is commonly used for traffic
/// inspection and routing without decrypting the payload.
///
/// The function scans the ClientHello extensions for the SNI extension and extracts
/// the first `host_name` entry within it.
///
/// # Arguments
/// * `payload` - Raw bytes of the TLS record, starting from the TLS record header.
///
/// # Returns
/// * `Some(String)` containing the SNI hostname if found and valid UTF-8.
/// * `None` if the payload is too short, not a TLS handshake record, or contains no SNI extension.
pub fn parse_tls_sni(payload: &[u8]) -> Option<String> {
    // A TLS ClientHello is at minimum 43 bytes before extensions begin.
    // Byte 0 must be 0x16, the content type for a TLS Handshake record.
    if payload.len() < 43 || payload[0] != 0x16 {
        return None;
    }

    // Scan from byte 43 onward, where TLS extensions typically begin.
    // This is a heuristic scan; a strict parser would follow length fields through
    // the record, handshake, and ClientHello layers to locate extensions precisely.
    let mut i = 43;
    while i + 9 < payload.len() {
        // The SNI extension type is 0x0000 (two-byte big-endian value).
        if payload[i] == 0x00 && payload[i + 1] == 0x00 {
            // Bytes i+2..i+3: extension data length (unused here).
            // Bytes i+4..i+5: SNI list length (unused here).
            // Byte  i+6:      name type (0x00 = host_name).
            // Bytes i+7..i+8: length of the hostname that follows.
            let len = ((payload[i + 7] as usize) << 8) | payload[i + 8] as usize;
            let start = i + 9;

            if start + len <= payload.len() {
                return std::str::from_utf8(&payload[start..start + len])
                    .ok()
                    .map(|s| s.to_string());
            }

            // Extension was found but the hostname length exceeds the remaining payload;
            // the packet is malformed, so stop scanning.
            break;
        }
        i += 1;
    }

    None
}