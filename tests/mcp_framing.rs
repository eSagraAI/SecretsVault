//! MCP stdio framing: oversized and non-UTF-8 input must yield a controlled
//! JSON-RPC `-32700` and never kill the session (N2: unbounded pre-cap read,
//! N3: `read_line` UTF-8 abort). In-process against `svault::mcp::serve` with
//! `ping` (answered without touching the broker), so no daemon, no sockets,
//! safe to run in parallel.

use std::io::Read;
use std::path::Path;

use serde_json::Value;
use svault::wire::MAX_MESSAGE_LEN;

const SOCK: &str = "/nonexistent-svault-framing-test.sock";

/// Drive one `serve` session over an in-memory stdin; return the result plus
/// each stdout line parsed as JSON.
fn serve_bytes(input: &[u8]) -> (Result<(), String>, Vec<Value>) {
    let mut stdin: &[u8] = input;
    let mut out = Vec::new();
    let res =
        svault::mcp::serve(Path::new(SOCK), None, &mut stdin, &mut out).map_err(|e| e.to_string());
    let replies: Vec<Value> = String::from_utf8(out)
        .expect("adapter output is UTF-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("reply line is JSON"))
        .collect();
    (res, replies)
}

fn ping(id: i64) -> Vec<u8> {
    format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"ping\",\"params\":{{}}}}\n")
        .into_bytes()
}

#[test]
fn control_small_valid_ping_is_answered() {
    let (res, replies) = serve_bytes(&ping(1));
    assert!(res.is_ok(), "serve failed on valid input: {res:?}");
    assert_eq!(replies.len(), 1, "one request → one reply");
    assert_eq!(replies[0]["id"], 1);
    assert_eq!(replies[0]["result"], serde_json::json!({}));
}

#[test]
fn oversized_line_with_newline_gets_32700_and_session_continues() {
    let mut input = vec![b'A'; MAX_MESSAGE_LEN + 100];
    input.push(b'\n');
    input.extend_from_slice(&ping(7));
    let (res, replies) = serve_bytes(&input);
    assert!(res.is_ok(), "serve failed: {res:?}");
    assert_eq!(replies.len(), 2, "oversize frame + ping → two replies");
    assert_eq!(replies[0]["error"]["code"], -32700);
    assert_eq!(replies[0]["id"], Value::Null);
    assert!(
        replies[0]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("too large"),
        "unexpected message: {}",
        replies[0]
    );
    assert_eq!(
        replies[1]["id"], 7,
        "session continues after oversize frame"
    );
    assert_eq!(replies[1]["result"], serde_json::json!({}));
}

#[test]
fn oversized_line_without_newline_then_eof_gets_32700_and_closes_cleanly() {
    // No trailing newline: EOF ends the frame. Must still be one controlled
    // error and a clean shutdown, never an abort.
    let input = vec![b'A'; MAX_MESSAGE_LEN + 100];
    let (res, replies) = serve_bytes(&input);
    assert!(res.is_ok(), "serve failed: {res:?}");
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0]["error"]["code"], -32700);
    assert_eq!(replies[0]["id"], Value::Null);
}

/// Newline-free flood that ends in EOF: the adapter must stop pulling input
/// once its scan budget is spent, not buffer the whole frame (N2).
struct Flood {
    remaining: usize,
    bytes_read: usize,
}

impl Read for Flood {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let n = buf.len().min(self.remaining).min(8192);
        buf[..n].fill(b'A');
        self.remaining -= n;
        self.bytes_read += n;
        Ok(n)
    }
}

#[test]
fn newline_free_flood_consumes_bounded_input_then_closes_cleanly() {
    let mut input = Flood {
        remaining: 8 * 1024 * 1024,
        bytes_read: 0,
    };
    let mut out = Vec::new();
    let res =
        svault::mcp::serve(Path::new(SOCK), None, &mut input, &mut out).map_err(|e| e.to_string());
    assert!(res.is_ok(), "serve failed on flood: {res:?}");
    assert!(
        input.bytes_read <= 3 * 1024 * 1024,
        "adapter pulled {} bytes for one newline-free frame: read is unbounded (N2)",
        input.bytes_read
    );
    let replies: Vec<Value> = String::from_utf8(out)
        .expect("adapter output is UTF-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("reply line is JSON"))
        .collect();
    assert_eq!(replies.len(), 1, "flood → one controlled error, then close");
    assert_eq!(replies[0]["error"]["code"], -32700);
}

#[test]
fn invalid_utf8_at_line_start_gets_32700_and_session_continues() {
    let mut input = vec![0xFF, 0xFE, b'\n'];
    input.extend_from_slice(&ping(3));
    let (res, replies) = serve_bytes(&input);
    assert!(res.is_ok(), "serve died on invalid UTF-8: {res:?}");
    assert_eq!(replies.len(), 2, "session must continue after a bad frame");
    assert_eq!(replies[0]["error"]["code"], -32700);
    assert_eq!(replies[0]["id"], Value::Null);
    assert_eq!(replies[1]["id"], 3);
    assert_eq!(replies[1]["result"], serde_json::json!({}));
}

#[test]
fn invalid_utf8_midstream_does_not_kill_following_requests() {
    let mut input = ping(1);
    input.push(0xFF);
    input.push(b'\n');
    input.extend_from_slice(&ping(2));
    let (res, replies) = serve_bytes(&input);
    assert!(
        res.is_ok(),
        "serve died mid-stream on invalid UTF-8: {res:?}"
    );
    assert_eq!(replies.len(), 3, "ping, bad frame, ping → three replies");
    assert_eq!(replies[0]["id"], 1);
    assert_eq!(replies[1]["error"]["code"], -32700);
    assert_eq!(replies[2]["id"], 2);
    assert_eq!(replies[2]["result"], serde_json::json!({}));
}
