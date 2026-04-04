use std::net::IpAddr;

use crate::{PortInfo, TcpState};

/// Parse a portview JSON array (as emitted by `--json`) back into `Vec<PortInfo>`.
///
/// The parser is intentionally minimal — it handles the exact format produced by
/// `port_info_json()` and tolerates missing optional fields (`ppid`, `local_addr`)
/// for backwards compatibility with older portview versions.
pub(crate) fn parse_port_json(input: &str) -> Result<Vec<PortInfo>, String> {
    let input = input.trim();

    // Must start with '[' and end with ']'
    if !input.starts_with('[') || !input.ends_with(']') {
        return Err(format!(
            "expected JSON array, got: {}",
            &input[..input.len().min(40)]
        ));
    }

    let inner = &input[1..input.len() - 1].trim();

    if inner.is_empty() {
        return Ok(vec![]);
    }

    let objects = split_objects(inner)?;
    let mut result = Vec::with_capacity(objects.len());
    for obj in objects {
        result.push(parse_object(obj.trim())?);
    }
    Ok(result)
}

/// Split the inner content of a JSON array into individual top-level `{…}` objects.
/// Uses brace-depth tracking so nested objects (e.g. docker arrays) don't confuse it.
fn split_objects(s: &str) -> Result<Vec<&str>, String> {
    let mut objects = Vec::new();
    let mut depth: i32 = 0;
    let mut in_string = false;
    let mut escape_next = false;
    let mut start: Option<usize> = None;

    for (i, c) in s.char_indices() {
        if escape_next {
            escape_next = false;
            continue;
        }
        if in_string {
            match c {
                '\\' => escape_next = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '{' => {
                if depth == 0 {
                    start = Some(i);
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(s_pos) = start {
                        objects.push(&s[s_pos..=i]);
                        start = None;
                    }
                }
            }
            _ => {}
        }
    }

    if depth != 0 {
        return Err("unbalanced braces in JSON".to_string());
    }

    Ok(objects)
}

/// Parse a single JSON object `{…}` into a `PortInfo`.
fn parse_object(obj: &str) -> Result<PortInfo, String> {
    if !obj.starts_with('{') || !obj.ends_with('}') {
        return Err(format!(
            "expected JSON object, got: {}",
            &obj[..obj.len().min(40)]
        ));
    }

    // Collect key-value pairs at the top level only (depth == 1)
    let inner = &obj[1..obj.len() - 1];
    let pairs = extract_pairs(inner)?;

    let mut port: Option<u16> = None;
    let mut protocol = String::new();
    let mut pid: Option<u32> = None;
    let mut ppid: u32 = 0;
    let mut process_name = String::new();
    let mut command = String::new();
    let mut user = String::new();
    let mut state = TcpState::Unknown;
    let mut memory_bytes: u64 = 0;
    let mut cpu_seconds: f64 = 0.0;
    let mut children: u32 = 0;
    let mut local_addr: IpAddr = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);

    for (key, value) in &pairs {
        match key.as_str() {
            "port" => port = Some(parse_u64(value)? as u16),
            "protocol" => protocol = parse_string(value)?,
            "pid" => pid = Some(parse_u64(value)? as u32),
            "ppid" => ppid = parse_u64(value)? as u32,
            "process" => process_name = parse_string(value)?,
            "command" => command = parse_string(value)?,
            "user" => user = parse_string(value)?,
            "state" => state = TcpState::from_state_str(&parse_string(value)?),
            "memory_bytes" => memory_bytes = parse_u64(value)?,
            "cpu_seconds" => cpu_seconds = parse_f64(value)?,
            "children" => children = parse_u64(value)? as u32,
            "local_addr" => {
                let s = parse_string(value)?;
                local_addr = s
                    .parse::<IpAddr>()
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            }
            // "docker" and any other unknown fields are ignored
            _ => {}
        }
    }

    let port = port.ok_or_else(|| "missing required field: port".to_string())?;
    let pid = pid.ok_or_else(|| "missing required field: pid".to_string())?;

    Ok(PortInfo {
        port,
        protocol,
        pid,
        ppid,
        process_name,
        command,
        user,
        state,
        memory_bytes,
        cpu_seconds,
        start_time: None,
        children,
        local_addr,
    })
}

/// Extract top-level key/value string pairs from the interior of a JSON object.
/// Values are returned as raw JSON sub-strings (string values include their quotes).
fn extract_pairs(s: &str) -> Result<Vec<(String, String)>, String> {
    let mut pairs = Vec::new();
    let mut pos = 0;
    let bytes = s.as_bytes();

    while pos < s.len() {
        // skip whitespace and commas
        while pos < s.len()
            && (bytes[pos] == b' '
                || bytes[pos] == b'\t'
                || bytes[pos] == b'\n'
                || bytes[pos] == b'\r'
                || bytes[pos] == b',')
        {
            pos += 1;
        }
        if pos >= s.len() {
            break;
        }

        // expect '"' for key
        if bytes[pos] != b'"' {
            return Err(format!("expected '\"' at position {}", pos));
        }
        let (key, after_key) = read_json_string(s, pos)?;
        pos = after_key;

        // skip whitespace then ':'
        while pos < s.len() && (bytes[pos] == b' ' || bytes[pos] == b'\t') {
            pos += 1;
        }
        if pos >= s.len() || bytes[pos] != b':' {
            return Err(format!("expected ':' after key \"{}\"", key));
        }
        pos += 1; // skip ':'

        // skip whitespace
        while pos < s.len() && (bytes[pos] == b' ' || bytes[pos] == b'\t') {
            pos += 1;
        }
        if pos >= s.len() {
            return Err(format!("expected value for key \"{}\"", key));
        }

        // read value (string, number, array, or nested object)
        let (raw_value, after_value) = read_json_value(s, pos)?;
        pos = after_value;

        pairs.push((key, raw_value));
    }

    Ok(pairs)
}

/// Read a JSON string starting at `pos` (which must point at `"`).
/// Returns (unescaped string content, position after closing `"`).
fn read_json_string(s: &str, pos: usize) -> Result<(String, usize), String> {
    debug_assert_eq!(s.as_bytes()[pos], b'"');
    let mut result = String::new();
    // Work with char indices so we handle multi-byte UTF-8 correctly.
    let s_chars: Vec<(usize, char)> = s.char_indices().collect();

    // find the char index corresponding to byte pos+1 (first char inside the string)
    let start_char_idx = s_chars.partition_point(|(byte_pos, _)| *byte_pos < pos + 1);
    let mut char_idx = start_char_idx;

    loop {
        if char_idx >= s_chars.len() {
            return Err("unterminated string".to_string());
        }
        let (byte_pos, c) = s_chars[char_idx];
        match c {
            '"' => {
                // closing quote — return position after it
                return Ok((result, byte_pos + 1));
            }
            '\\' => {
                char_idx += 1;
                if char_idx >= s_chars.len() {
                    return Err("unexpected end after backslash".to_string());
                }
                let (_, esc) = s_chars[char_idx];
                match esc {
                    '"' => result.push('"'),
                    '\\' => result.push('\\'),
                    '/' => result.push('/'),
                    'n' => result.push('\n'),
                    'r' => result.push('\r'),
                    't' => result.push('\t'),
                    'b' => result.push('\x08'),
                    'f' => result.push('\x0C'),
                    'u' => {
                        // read 4 hex digits
                        let mut hex = String::new();
                        for _ in 0..4 {
                            char_idx += 1;
                            if char_idx >= s_chars.len() {
                                return Err("short \\u escape".to_string());
                            }
                            hex.push(s_chars[char_idx].1);
                        }
                        let code = u32::from_str_radix(&hex, 16)
                            .map_err(|_| format!("invalid \\u escape: {}", hex))?;
                        result.push(
                            char::from_u32(code)
                                .ok_or_else(|| format!("invalid unicode codepoint: {}", code))?,
                        );
                    }
                    other => {
                        result.push('\\');
                        result.push(other);
                    }
                }
            }
            other => result.push(other),
        }
        char_idx += 1;
    }
}

/// Read a JSON value (string, number, array, nested object) starting at `pos`.
/// Returns (raw text, position after the value).
fn read_json_value(s: &str, pos: usize) -> Result<(String, usize), String> {
    let bytes = s.as_bytes();
    match bytes[pos] {
        b'"' => {
            // string — find end
            let end = find_string_end(s, pos)?;
            Ok((s[pos..end].to_string(), end))
        }
        b'[' | b'{' => {
            // nested structure — use depth tracking
            let end = find_nested_end(s, pos)?;
            Ok((s[pos..end].to_string(), end))
        }
        _ => {
            // number, true, false, null — read until ',' or '}' or ']' or whitespace
            let mut end = pos;
            while end < s.len()
                && bytes[end] != b','
                && bytes[end] != b'}'
                && bytes[end] != b']'
                && bytes[end] != b' '
                && bytes[end] != b'\t'
                && bytes[end] != b'\n'
                && bytes[end] != b'\r'
            {
                end += 1;
            }
            Ok((s[pos..end].to_string(), end))
        }
    }
}

/// Advance past a JSON string starting at `pos` (which points at `"`).
/// Returns the byte position *after* the closing `"`.
fn find_string_end(s: &str, pos: usize) -> Result<usize, String> {
    let bytes = s.as_bytes();
    let mut i = pos + 1;
    while i < s.len() {
        match bytes[i] {
            b'\\' => i += 2, // skip escaped char
            b'"' => return Ok(i + 1),
            _ => i += 1,
        }
    }
    Err("unterminated JSON string".to_string())
}

/// Advance past a nested `{…}` or `[…]` starting at `pos`.
/// Returns the byte position *after* the closing brace/bracket.
fn find_nested_end(s: &str, pos: usize) -> Result<usize, String> {
    let bytes = s.as_bytes();
    let mut depth: i32 = 0;
    let mut in_str = false;
    let mut i = pos;
    while i < s.len() {
        if in_str {
            match bytes[i] {
                b'\\' => i += 2,
                b'"' => {
                    in_str = false;
                    i += 1;
                }
                _ => i += 1,
            }
            continue;
        }
        match bytes[i] {
            b'"' => {
                in_str = true;
                i += 1;
            }
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return Ok(i);
                }
            }
            _ => i += 1,
        }
    }
    Err("unterminated nested JSON structure".to_string())
}

fn parse_u64(s: &str) -> Result<u64, String> {
    s.trim()
        .parse::<u64>()
        .map_err(|_| format!("expected integer, got: {}", s))
}

fn parse_f64(s: &str) -> Result<f64, String> {
    s.trim()
        .parse::<f64>()
        .map_err(|_| format!("expected float, got: {}", s))
}

/// Parse a JSON string value (raw value includes surrounding quotes).
fn parse_string(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if !raw.starts_with('"') {
        return Err(format!("expected JSON string, got: {}", raw));
    }
    // Use the same unescape logic via read_json_string
    let (s, _) = read_json_string(raw, 0)?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_port() {
        let json = r#"[{"port":3000,"protocol":"TCP","pid":1234,"ppid":1,"process":"node","command":"next dev","user":"mark","state":"LISTEN","memory_bytes":248000000,"cpu_seconds":14.3,"children":3,"local_addr":"0.0.0.0"}]"#;
        let ports = parse_port_json(json).unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 3000);
        assert_eq!(ports[0].pid, 1234);
        assert_eq!(ports[0].ppid, 1);
        assert_eq!(ports[0].process_name, "node");
        assert_eq!(ports[0].state, TcpState::Listen);
    }

    #[test]
    fn parse_empty_array() {
        let ports = parse_port_json("[]").unwrap();
        assert!(ports.is_empty());
    }

    #[test]
    fn parse_invalid_json() {
        assert!(parse_port_json("not json").is_err());
    }

    #[test]
    fn parse_missing_optional_fields() {
        let json = r#"[{"port":80,"protocol":"TCP","pid":100,"process":"nginx","command":"nginx","user":"root","state":"LISTEN","memory_bytes":50000,"cpu_seconds":1.0,"children":2}]"#;
        let ports = parse_port_json(json).unwrap();
        assert_eq!(ports[0].ppid, 0);
        assert_eq!(ports[0].port, 80);
    }
}
