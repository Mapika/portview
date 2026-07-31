//! Minimal hand-rolled JSON reader.
//!
//! portview emits JSON by hand (see `json_escape` / `port_info_json` in main.rs)
//! and needs to read it back in two places: SSH remote mode parses `portview
//! --json` from the remote host, and MCP mode parses JSON-RPC requests from the
//! client. Keeping this in-tree avoids a serde dependency, which matters for a
//! tool whose pitch is a ~1 MB dependency-light binary.
//!
//! Values are handed back as *raw* JSON substrings — string values keep their
//! surrounding quotes and escapes. Use `parse_string` / `parse_u64` / `parse_f64`
//! (or the `get_*` helpers) to convert them.

// ── Object access ────────────────────────────────────────────────────

/// Extract top-level key/value pairs from a complete JSON object (braces included).
pub(crate) fn object_pairs(obj: &str) -> Result<Vec<(String, String)>, String> {
    let obj = obj.trim();
    if !obj.starts_with('{') || !obj.ends_with('}') {
        return Err(format!(
            "expected JSON object, got: {}",
            &obj[..obj.len().min(40)]
        ));
    }
    extract_pairs(&obj[1..obj.len() - 1])
}

/// Look up a key, returning its raw JSON value.
pub(crate) fn get<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// Look up a string-valued key, unescaped. Returns `None` if absent or not a string.
pub(crate) fn get_string(pairs: &[(String, String)], key: &str) -> Option<String> {
    get(pairs, key).and_then(|raw| parse_string(raw).ok())
}

/// Look up an integer-valued key. Returns `None` if absent or not an integer.
pub(crate) fn get_u64(pairs: &[(String, String)], key: &str) -> Option<u64> {
    get(pairs, key).and_then(|raw| parse_u64(raw).ok())
}

/// Look up a boolean-valued key. Returns `None` if absent or not a boolean.
pub(crate) fn get_bool(pairs: &[(String, String)], key: &str) -> Option<bool> {
    match get(pairs, key)?.trim() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

// ── Scanning ─────────────────────────────────────────────────────────

/// Extract top-level key/value string pairs from the interior of a JSON object.
/// Values are returned as raw JSON sub-strings (string values include their quotes).
pub(crate) fn extract_pairs(s: &str) -> Result<Vec<(String, String)>, String> {
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
pub(crate) fn read_json_string(s: &str, pos: usize) -> Result<(String, usize), String> {
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
pub(crate) fn read_json_value(s: &str, pos: usize) -> Result<(String, usize), String> {
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
pub(crate) fn find_string_end(s: &str, pos: usize) -> Result<usize, String> {
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
pub(crate) fn find_nested_end(s: &str, pos: usize) -> Result<usize, String> {
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

// ── Value conversion ─────────────────────────────────────────────────

pub(crate) fn parse_u64(s: &str) -> Result<u64, String> {
    s.trim()
        .parse::<u64>()
        .map_err(|_| format!("expected integer, got: {}", s))
}

pub(crate) fn parse_f64(s: &str) -> Result<f64, String> {
    s.trim()
        .parse::<f64>()
        .map_err(|_| format!("expected float, got: {}", s))
}

/// Parse a JSON string value (raw value includes surrounding quotes).
pub(crate) fn parse_string(raw: &str) -> Result<String, String> {
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
    fn pairs_from_flat_object() {
        let pairs = object_pairs(r#"{"a":1,"b":"two","c":true}"#).unwrap();
        assert_eq!(get(&pairs, "a"), Some("1"));
        assert_eq!(get_string(&pairs, "b").as_deref(), Some("two"));
        assert_eq!(get_bool(&pairs, "c"), Some(true));
        assert_eq!(get(&pairs, "missing"), None);
    }

    #[test]
    fn nested_values_stay_raw() {
        let pairs = object_pairs(r#"{"params":{"name":"x","args":[1,2]},"id":7}"#).unwrap();
        assert_eq!(get(&pairs, "params"), Some(r#"{"name":"x","args":[1,2]}"#));
        assert_eq!(get_u64(&pairs, "id"), Some(7));
    }

    #[test]
    fn braces_inside_strings_do_not_confuse_depth() {
        let pairs = object_pairs(r#"{"cmd":"sh -c '{ }'","port":80}"#).unwrap();
        assert_eq!(get_string(&pairs, "cmd").as_deref(), Some("sh -c '{ }'"));
        assert_eq!(get_u64(&pairs, "port"), Some(80));
    }

    #[test]
    fn escapes_are_unescaped() {
        let pairs = object_pairs(r#"{"s":"a\"b\\c\ndA"}"#).unwrap();
        assert_eq!(get_string(&pairs, "s").as_deref(), Some("a\"b\\c\ndA"));
    }

    #[test]
    fn wrong_type_yields_none_not_panic() {
        let pairs = object_pairs(r#"{"n":"notanumber","b":42}"#).unwrap();
        assert_eq!(get_u64(&pairs, "n"), None);
        assert_eq!(get_bool(&pairs, "b"), None);
        assert_eq!(get_string(&pairs, "b"), None);
    }

    #[test]
    fn non_object_rejected() {
        assert!(object_pairs("[1,2,3]").is_err());
        assert!(object_pairs("not json").is_err());
    }
}
