//! Deterministic dotenv serialization for `inject_file`.
//!
//! `.env` is treated as dotenv data, never shell. Values are written as
//! double-quoted dotenv strings with full escaping (`\\`, `\"`, `\$`, `\n`,
//! `\r`, `\t`); simple values are written bare. Keys are emitted sorted for
//! byte-determinism. Roundtrip equality (byte-for-byte value recovery) is
//! proven against an independent parser (dotenvy) in the tests.
//!
//! Values MUST be UTF-8 without control characters other than `\n`, `\r`,
//! `\t` — validated here and at `secret.set` injection time.

use crate::error::VaultError;

pub struct Entry {
    pub key: String,
    pub value: String,
}

/// Serialize entries deterministically: sorted by key, `KEY=value` or
/// `KEY="escaped"`, LF line endings, trailing newline.
pub fn serialize(entries: &[Entry]) -> Result<Vec<u8>, VaultError> {
    let mut sorted: Vec<&Entry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.key.cmp(&b.key));
    // Duplicate keys would make the file ambiguous — reject.
    for pair in sorted.windows(2) {
        if pair[0].key == pair[1].key {
            return Err(VaultError::InvalidInput("duplicate keys in injection"));
        }
    }
    let mut out = String::new();
    for e in sorted {
        if !crate::model::valid_key(&e.key) {
            return Err(VaultError::InvalidInput("invalid key name"));
        }
        validate_value(&e.value)?;
        out.push_str(&e.key);
        out.push('=');
        out.push_str(&escape_value(&e.value));
        out.push('\n');
    }
    Ok(out.into_bytes())
}

pub fn validate_value(value: &str) -> Result<(), VaultError> {
    if value
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(VaultError::InvalidInput(
            "secret value contains control characters not representable in dotenv",
        ));
    }
    Ok(())
}

/// Quote/escape rules (verified empirically against dotenvy, the
/// independent parser used in the roundtrip tests): bare when the value
/// cannot be misread; otherwise double-quoted with `\\`, `\"` and `\$`
/// escaped, and raw newlines/tabs preserved inside the quotes (multi-line
/// quoted values). A bare `$` inside double quotes is a parse error in
/// dotenvy, which is why it is always escaped — variable expansion can
/// never rewrite a value.
fn escape_value(value: &str) -> String {
    let needs_quotes = value.is_empty()
        || value.chars().any(|c| {
            c.is_whitespace()
                || matches!(c, '"' | '\'' | '$' | '`' | '#' | '=' | '\\')
                || c.is_control()
        });
    if !needs_quotes {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '$' => out.push_str("\\$"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(entries: &[Entry]) {
        let bytes = serialize(entries).unwrap();
        let cursor = std::io::Cursor::new(&bytes);
        let iter = dotenvy::from_read_iter(cursor);
        let parsed: std::collections::HashMap<String, String> =
            iter.map(|r| r.expect("dotenv parse")).collect();
        assert_eq!(parsed.len(), entries.len());
        for e in entries {
            assert_eq!(
                parsed.get(&e.key).map(String::as_str),
                Some(e.value.as_str()),
                "value for {} must roundtrip byte-for-byte",
                e.key
            );
        }
    }

    #[test]
    fn simple_values_are_bare_and_sorted() {
        let bytes = serialize(&[
            Entry {
                key: "B_KEY".into(),
                value: "two".into(),
            },
            Entry {
                key: "A_KEY".into(),
                value: "one".into(),
            },
        ])
        .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(text, "A_KEY=one\nB_KEY=two\n");
    }

    #[test]
    fn adversarial_values_roundtrip_exactly() {
        roundtrip(&[
            Entry {
                key: "SPACES".into(),
                value: "hello world  ".into(),
            },
            Entry {
                key: "QUOTES".into(),
                value: "he said \"hi\" and 'bye'".into(),
            },
            Entry {
                key: "DOLLAR".into(),
                value: "cost $100 and ${VAR} and $HOME".into(),
            },
            Entry {
                key: "BACKTICK".into(),
                value: "run `whoami`".into(),
            },
            Entry {
                key: "HASH".into(),
                value: "value # not a comment".into(),
            },
            Entry {
                key: "EQUALS".into(),
                value: "a=b=c".into(),
            },
            Entry {
                key: "UNICODE".into(),
                value: "café 中文 🔐".into(),
            },
            Entry {
                key: "NEWLINES".into(),
                value: "line1\nline2\r\nline3\tend".into(),
            },
            Entry {
                key: "BACKSLASH".into(),
                value: "C:\\path\\to".into(),
            },
            Entry {
                key: "EMPTYISH".into(),
                value: " ".into(),
            },
        ]);
    }

    #[test]
    fn dollar_expansion_can_never_rewrite_values() {
        // A reader that expands $VARS must still recover the literal bytes.
        roundtrip(&[
            Entry {
                key: "EXPANSION".into(),
                value: "${HOME}/$PATH".into(),
            },
            Entry {
                key: "NESTED".into(),
                value: "$\"quoted\"$".into(),
            },
        ]);
    }

    #[test]
    fn control_characters_are_rejected() {
        let mut bad = String::from("ok");
        bad.push('\u{0}');
        assert!(validate_value(&bad).is_err());
        assert!(validate_value("fine\nvalues\r\tok").is_ok());
        assert!(validate_value("café ✓").is_ok());
    }

    #[test]
    fn duplicate_keys_rejected() {
        assert!(
            serialize(&[
                Entry {
                    key: "A".into(),
                    value: "1".into()
                },
                Entry {
                    key: "A".into(),
                    value: "2".into()
                },
            ])
            .is_err()
        );
    }
}
