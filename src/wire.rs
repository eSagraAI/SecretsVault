//! Wire protocol v1: newline-delimited JSON over the Unix domain socket.
//!
//! One request per connection in Phase 3. Requests carry an optional agent
//! token (absent = human owner); responses never contain secret values for
//! the agent-reachable ops. Messages are capped at 1 MiB.

use std::io::{BufRead, Write};

use serde::{Deserialize, Serialize};

use crate::error::VaultError;

pub const VERSION: u32 = 1;
pub const MAX_MESSAGE_LEN: usize = 1024 * 1024;

/// Request credentials. Exactly one of the three should be present:
/// `token` authenticates an agent; `passphrase` is the human proof
/// (entered interactively and verified against the vault's key slots);
/// `session` is a server-minted human-session credential (see Human session).
/// Absent auth = unauthenticated — never treated as human.
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthField {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Request {
    pub v: u32,
    pub id: String,
    pub op: String,
    #[serde(default)]
    pub auth: Option<AuthField>,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WireError {
    pub code: String,
    pub msg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Box<serde_json::Value>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Response {
    pub v: u32,
    pub id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<WireError>,
}

impl Response {
    pub fn ok(id: &str, result: serde_json::Value) -> Self {
        Self {
            v: VERSION,
            id: id.to_string(),
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: &str, code: &str, msg: impl Into<String>) -> Self {
        Self {
            v: VERSION,
            id: id.to_string(),
            ok: false,
            result: None,
            error: Some(WireError {
                code: code.to_string(),
                msg: msg.into(),
                data: None,
            }),
        }
    }

    pub fn err_data(id: &str, code: &str, msg: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            v: VERSION,
            id: id.to_string(),
            ok: false,
            result: None,
            error: Some(WireError {
                code: code.to_string(),
                msg: msg.into(),
                data: Some(Box::new(data)),
            }),
        }
    }
}

/// Read one newline-terminated message, bounded at `MAX_MESSAGE_LEN`.
fn read_line_bounded<R: BufRead>(stream: &mut R) -> Result<Vec<u8>, VaultError> {
    let mut buf = Vec::new();
    loop {
        let available = stream.fill_buf().map_err(VaultError::from)?;
        if available.is_empty() {
            if buf.is_empty() {
                return Err(VaultError::Protocol("connection closed".into()));
            }
            return Err(VaultError::Protocol("unterminated message".into()));
        }
        let chunk_len = available.len();
        match available.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                buf.extend_from_slice(&available[..pos]);
                stream.consume(pos + 1);
                if buf.len() > MAX_MESSAGE_LEN {
                    return Err(VaultError::TooLarge);
                }
                return Ok(buf);
            }
            None => {
                buf.extend_from_slice(available);
                stream.consume(chunk_len);
                if buf.len() > MAX_MESSAGE_LEN {
                    return Err(VaultError::TooLarge);
                }
            }
        }
    }
}

/// Read one newline-terminated request, bounded at `MAX_MESSAGE_LEN`.
pub fn read_request<R: BufRead>(stream: &mut R) -> Result<Request, VaultError> {
    let buf = read_line_bounded(stream)?;
    let req: Request =
        serde_json::from_slice(&buf).map_err(|_| VaultError::Protocol("invalid request".into()))?;
    if req.v != VERSION {
        return Err(VaultError::Protocol("unsupported protocol version".into()));
    }
    Ok(req)
}

/// Read one newline-terminated response.
pub fn read_response<R: BufRead>(stream: &mut R) -> Result<Response, VaultError> {
    let buf = read_line_bounded(stream)?;
    let resp: Response = serde_json::from_slice(&buf)
        .map_err(|_| VaultError::Protocol("invalid response".into()))?;
    if resp.v != VERSION {
        return Err(VaultError::Protocol("unsupported protocol version".into()));
    }
    Ok(resp)
}

pub fn write_response(stream: &mut impl Write, response: &Response) -> Result<(), VaultError> {
    let mut line = serde_json::to_string(response)
        .map_err(|e| VaultError::Protocol(format!("response serialization: {e}")))?;
    line.push('\n');
    stream.write_all(line.as_bytes())?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_line(json: &str) -> Vec<u8> {
        let mut v = json.as_bytes().to_vec();
        v.push(b'\n');
        v
    }

    #[test]
    fn request_roundtrip() {
        let mut stream = std::io::Cursor::new(request_line(
            r#"{"v":1,"id":"r1","op":"secrets.list","auth":{"token":"tok"},"params":{"project":"acme"}}"#,
        ));
        let req = read_request(&mut stream).unwrap();
        assert_eq!(req.v, 1);
        assert_eq!(req.op, "secrets.list");
        assert_eq!(req.auth.unwrap().token.unwrap(), "tok");
        assert_eq!(req.params["project"], "acme");
    }

    #[test]
    fn request_with_passphrase_proof_roundtrip() {
        let mut stream = std::io::Cursor::new(request_line(
            r#"{"v":1,"id":"r2","op":"project.add","auth":{"passphrase":"pw"},"params":{"name":"p"}}"#,
        ));
        let req = read_request(&mut stream).unwrap();
        assert_eq!(req.auth.unwrap().passphrase.unwrap(), "pw");
    }

    #[test]
    fn human_request_has_no_auth() {
        let mut stream = std::io::Cursor::new(request_line(
            r#"{"v":1,"id":"r2","op":"vault.status","params":{}}"#,
        ));
        let req = read_request(&mut stream).unwrap();
        assert!(req.auth.is_none());
    }

    #[test]
    fn wrong_version_rejected() {
        let mut stream = std::io::Cursor::new(request_line(
            r#"{"v":2,"id":"r3","op":"vault.status","params":{}}"#,
        ));
        assert!(matches!(
            read_request(&mut stream),
            Err(VaultError::Protocol(_))
        ));
    }

    #[test]
    fn malformed_json_rejected() {
        let mut stream = std::io::Cursor::new(request_line("{not json"));
        assert!(matches!(
            read_request(&mut stream),
            Err(VaultError::Protocol(_))
        ));
    }

    #[test]
    fn oversized_message_rejected() {
        // A line far beyond the cap: only MAX+2 bytes are ever read, and the
        // missing terminator makes the cap unambiguous.
        let mut stream = std::io::Cursor::new(vec![b'a'; MAX_MESSAGE_LEN + 32]);
        assert!(matches!(
            read_request(&mut stream),
            Err(VaultError::TooLarge)
        ));
    }

    #[test]
    fn response_roundtrip_shape() {
        let resp = Response::ok("r1", serde_json::json!({"keys": ["A"]}));
        let text = serde_json::to_string(&resp).unwrap();
        assert!(text.contains("\"ok\":true"));
        assert!(text.contains("\"keys\":[\"A\"]"));
        assert!(!text.contains("error"));

        let err = Response::err("r2", "E_PERMISSION", "no grant");
        let text = serde_json::to_string(&err).unwrap();
        assert!(text.contains("\"ok\":false"));
        assert!(text.contains("E_PERMISSION"));
    }
}
