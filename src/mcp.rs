//! MCP adapter: a thin stdio JSON-RPC ↔ broker UDS translator.
//!
//! It exposes exactly six agent tools (`list_secrets`, `inject_file`,
//! `reveal`, `approval_status`, `lease_create`, `lease_revoke`) and forwards
//! each call as one broker request over the Unix domain socket. It contains
//! zero authorization or security decisions: the broker authenticates,
//! authorizes, audits, and redacts; this layer only translates framing and
//! maps broker failures to `isError` tool results. Broker messages never
//! carry secrets by construction, so forwarding their code/message/data adds
//! no credential material; the only value ever returned is an intentionally
//! approved `reveal` claim.
//!
//! **Lease credentials stay inside this process.** `lease/create` yields a
//! one-time 256-bit credential, which the adapter keeps in a session-local
//! map keyed by the public `lease_id` handle and never forwards to the
//! model in any response. Later tool calls naming that handle have the
//! credential substituted on the wire (`params.lease`), so an LLM
//! transcript, a tool result, or a prompt log never contains a usable
//! capability.
//!
//! Framing is newline-delimited JSON-RPC 2.0 on stdio (one object per line),
//! served synchronously on `std` — no async runtime, no MCP framework.
//! Human-only tools (`approvals.approve`/`deny`/`pending`), management ops,
//! and `run`/`run_signal` are absent, never errors: the adapter cannot reach
//! what it does not name.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::Path;

use serde_json::{Value, json};

use crate::VaultError;
use crate::client::{Auth, BrokerError, broker_call_with_auth};
/// One broker request over a fresh UDS connection: send, read the single
/// response line, close. Agent surface: `Auth::Session` is refused BEFORE any
/// I/O (C-04/S-16: a human capability must never enter a model transcript
/// or tool result); every other `Auth` variant delegates to the single
/// shared transport in `client` (`broker_call_with_auth`), preserving the
/// exact wire code/message/data.
pub fn broker_call(
    socket: &Path,
    op: &str,
    auth: &Auth,
    params: Value,
) -> Result<Value, BrokerError> {
    // The MCP adapter is agent-only: it never presents a human session.
    // Refuse rather than forward — a capability must never enter a model
    // transcript or tool result (C-04/S-16). Before any I/O: no connection,
    // no handshake, zero bytes either way.
    if matches!(auth, Auth::Session(_)) {
        return Err(BrokerError::protocol(
            "human sessions are not available to agent tools",
        ));
    }
    broker_call_with_auth(socket, op, auth, params)
}

/// Tool name → broker op. Anything else is absent (unknown tool), never a
/// broker call. Exactly the six contracted agent tools.
fn tool_op(name: &str) -> Option<&'static str> {
    match name {
        "list_secrets" => Some("secrets.list"),
        "inject_file" => Some("inject_file"),
        "reveal" => Some("reveal"),
        "approval_status" => Some("approvals.status"),
        "lease_create" => Some("lease.create"),
        "lease_revoke" => Some("lease.revoke"),
        _ => None,
    }
}

/// Tools whose broker op is constrained by a lease credential. `lease_revoke`
/// is deliberately absent: revocation names the public handle, which is the
/// one operation a handle alone is allowed to drive.
fn consumes_lease(tool: &str) -> bool {
    matches!(tool, "list_secrets" | "inject_file" | "reveal")
}

fn str_prop(desc: &str) -> Value {
    json!({"type": "string", "description": desc})
}

/// The advertised tool set. Schemas are transport shapes only — every
/// semantic check (grants, leases, bindings, windows) stays broker-side.
fn tools_list() -> Value {
    json!([
        {
            "name": "list_secrets",
            "description": "List a project's secret key names and metadata — never values.",
            "inputSchema": {
                "type": "object",
                "required": ["project"],
                "properties": {
                    "project": str_prop("Project name"),
                    "lease_id": str_prop("Optional lease handle from lease_create (the credential stays server-side)")
                }
            }
        },
        {
            "name": "inject_file",
            "description": "Write project secrets to a dotenv file under an authorized folder; returns names and counts only.",
            "inputSchema": {
                "type": "object",
                "required": ["project", "path"],
                "properties": {
                    "project": str_prop("Project name"),
                    "path": str_prop("Relative destination path under an authorized folder"),
                    "keys": {"type": "array", "items": {"type": "string"}, "description": "Secret names to write (omitted = all)"},
                    "lease_id": str_prop("Optional lease handle from lease_create (the credential stays server-side)")
                }
            }
        },
        {
            "name": "reveal",
            "description": "Reveal one secret value. Without approval_id this requests approval (E_APPROVAL_PENDING with approval_id); with an approved approval_id it claims the value exactly once.",
            "inputSchema": {
                "type": "object",
                "required": ["project", "key"],
                "properties": {
                    "project": str_prop("Project name"),
                    "key": str_prop("Secret key name"),
                    "approval_id": str_prop("Approval from a prior pending reveal"),
                    "lease_id": str_prop("Optional lease handle from lease_create (the credential stays server-side)")
                }
            }
        },
        {
            "name": "approval_status",
            "description": "Poll an own approval's state: pending | approved | denied | expired | consumed.",
            "inputSchema": {
                "type": "object",
                "required": ["approval_id"],
                "properties": {
                    "approval_id": str_prop("Approval id from a pending reveal")
                }
            }
        },
        {
            "name": "lease_create",
            "description": "Create a lease: a TTL-bound subset of the caller's own grant on a project. Returns the public lease handle; the lease credential is retained server-side and is never returned to the model.",
            "inputSchema": {
                "type": "object",
                "required": ["project", "ops", "ttl_secs"],
                "properties": {
                    "project": str_prop("Project name"),
                    "ops": str_prop("Comma-separated op subset, e.g. read,inject"),
                    "ttl_secs": {"type": "integer", "minimum": 1, "description": "Time to live in seconds"}
                }
            }
        },
        {
            "name": "lease_revoke",
            "description": "Revoke an owned lease immediately.",
            "inputSchema": {
                "type": "object",
                "required": ["lease_id"],
                "properties": {
                    "lease_id": str_prop("Lease handle from lease_create")
                }
            }
        }
    ])
}

/// Adapter state: the broker auth, and the session-local lease credential
/// store. The store is the only place a lease credential ever lives on the
/// MCP side; it is never serialized into a tool result.
struct Adapter<'a> {
    socket: &'a Path,
    auth: &'a Auth,
    leases: HashMap<String, String>,
}

impl Adapter<'_> {
    /// Resolve the lease input for a lease-consuming tool.
    ///
    /// The only lease input a caller may name is the public `lease_id` handle,
    /// which this adapter maps to the credential it holds; the credential
    /// itself never crosses the adapter boundary. Two hostile shapes must fail
    /// closed rather than be forwarded:
    ///
    /// * a caller-supplied `lease` **credential** — that would put a live
    ///   capability on the wire (and into transcripts/logs) and would let the
    ///   model present a credential this adapter never issued;
    /// * a `lease_id` this adapter does not hold — forwarding without it would
    ///   silently widen the call to the caller's full grant.
    fn apply_lease(&self, args: &mut Value) -> Result<(), (&'static str, String)> {
        if args.get("lease").is_some_and(|v| !v.is_null()) {
            return Err((
                "E_INVALID_INPUT",
                "lease credentials are not accepted from the caller; use lease_id".to_string(),
            ));
        }
        let Some(handle) = args.get("lease_id").and_then(Value::as_str) else {
            return Ok(());
        };
        let handle = handle.to_string();
        let Some(credential) = self.leases.get(&handle) else {
            return Err(("E_LEASE_EXPIRED", format!("unknown lease: {handle}")));
        };
        args["lease"] = json!(credential);
        // The handle authorizes nothing and is not forwarded.
        if let Some(obj) = args.as_object_mut() {
            obj.remove("lease_id");
        }
        Ok(())
    }
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn rpc_error(id: Value, code: i64, message: String) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn handle_message(adapter: &mut Adapter, msg: &Value) -> Option<Value> {
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let has_id = msg.get("id").is_some_and(|v| !v.is_null());
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    match method {
        "initialize" => {
            // Echo the client's version when offered; framing only, nothing negotiated.
            let version = msg
                .get("params")
                .and_then(|p| p.get("protocolVersion"))
                .and_then(|v| v.as_str())
                .unwrap_or("2024-11-05");
            Some(rpc_result(
                id,
                json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "svault", "version": env!("CARGO_PKG_VERSION")}
                }),
            ))
        }
        "ping" => Some(rpc_result(id, json!({}))),
        "tools/list" => Some(rpc_result(id, json!({"tools": tools_list()}))),
        "tools/call" => {
            let params = msg.get("params").unwrap_or(&Value::Null);
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let mut args = params.get("arguments").cloned().unwrap_or(json!({}));
            let Some(op) = tool_op(name) else {
                return Some(rpc_error(id, -32602, format!("unknown tool: {name}")));
            };
            if !args.is_object() {
                args = json!({});
            }
            // Resolve the caller's `lease_id` handle to the adapter-held
            // credential; a caller-supplied credential is refused outright.
            // The credential never leaves this process.
            if consumes_lease(name)
                && let Err((code, why)) = adapter.apply_lease(&mut args)
            {
                let detail = json!({"code": code, "message": why});
                return Some(rpc_result(
                    id,
                    json!({"content": [{"type": "text", "text": detail.to_string()}], "isError": true}),
                ));
            }
            // Forward verbatim otherwise: no validation, no defaults, no policy here.
            match broker_call(adapter.socket, op, adapter.auth, args) {
                Ok(result) => {
                    let mut body = result;
                    if name == "lease_create" {
                        // Keep the credential; the model sees only the handle,
                        // its display prefix, and the window.
                        if let (Some(handle), Some(credential)) = (
                            body.get("lease_id").and_then(Value::as_str),
                            body.get("lease_credential").and_then(Value::as_str),
                        ) {
                            adapter
                                .leases
                                .insert(handle.to_string(), credential.to_string());
                        }
                        if let Some(obj) = body.as_object_mut() {
                            obj.remove("lease_credential");
                        }
                    }
                    if name == "lease_revoke" {
                        // A revoked lease can never be presented again; drop
                        // the credential so the handle stops resolving here.
                        if let Some(handle) = body
                            .get("lease_id")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                        {
                            adapter.leases.remove(&handle);
                        }
                    }
                    Some(rpc_result(
                        id,
                        json!({"content": [{"type": "text", "text": body.to_string()}] }),
                    ))
                }
                Err(e) => {
                    let mut detail = json!({"code": e.code, "message": e.msg});
                    if let Some(d) = e.data {
                        detail["data"] = d;
                    }
                    Some(rpc_result(
                        id,
                        json!({"content": [{"type": "text", "text": detail.to_string()}], "isError": true}),
                    ))
                }
            }
        }
        // Lifecycle notifications: acknowledge by silence.
        "notifications/initialized" | "notifications/cancelled" => None,
        "" => {
            if has_id {
                Some(rpc_error(id, -32600, "invalid request".to_string()))
            } else {
                None
            }
        }
        _ => {
            if has_id {
                Some(rpc_error(id, -32601, "method not found".to_string()))
            } else {
                None
            }
        }
    }
}

/// Hard ceiling on the bytes buffered for one stdin frame (payload without
/// the newline): mirrors `wire::MAX_MESSAGE_LEN`, so the adapter and the
/// broker agree on what "too large" means.
const FRAME_CAP: usize = crate::wire::MAX_MESSAGE_LEN;
/// Bound on the discard scan past an oversized line: resync to the next
/// newline when it arrives soon, so one fat line costs one `-32700` and the
/// session survives — but close cleanly instead of draining a newline-free
/// flood forever (N2). Worst case one oversized frame pulls ~2 MiB total.
const DRAIN_CAP: usize = crate::wire::MAX_MESSAGE_LEN;

/// One stdin frame. Split out so the serve loop never holds an unbounded
/// buffer and never lets one bad frame kill the session.
enum Frame {
    /// Complete line bytes without the trailing newline (may be empty).
    Line(Vec<u8>),
    /// No bytes pending and the peer closed stdin: end the session.
    Eof,
    /// The line exceeded `FRAME_CAP` before any newline. `resynced` is true
    /// when the terminating newline (or EOF) arrived within the drain
    /// budget, so the session may continue; false when the drain budget ran
    /// out, so the caller must close the session instead of draining
    /// forever.
    Oversize { resynced: bool },
}

/// Bounded line framing over `reader`: at most `FRAME_CAP` plus one `fill_buf`
/// chunk (~8 KiB) is ever buffered for one frame, so a peer that never sends
/// `\n` cannot force unbounded growth (N2 was `BufRead::read_line` into a
/// `String`, which grows without limit and also dies on non-UTF-8). The loop
/// mirrors `wire::read_line_bounded`; it returns raw bytes and leaves UTF-8
/// and JSON validation to the caller, so one bad frame is one `-32700`,
/// never a dead session (N3).
fn read_frame<R: BufRead>(reader: &mut R) -> std::io::Result<Frame> {
    let mut buf = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            // EOF: a partial line is still a frame (matches the old
            // `read_line` behavior, which returned short reads); no bytes
            // at all ends the session. A partial line here is always within
            // cap — anything larger already diverted to the drain below.
            if buf.is_empty() {
                return Ok(Frame::Eof);
            }
            return Ok(Frame::Line(buf));
        }
        let chunk_len = available.len();
        match available.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                buf.extend_from_slice(&available[..pos]);
                reader.consume(pos + 1);
                if buf.len() > FRAME_CAP {
                    // Newline arrived but the payload already exceeds the
                    // cap: oversized, and already resynced past the newline.
                    return Ok(Frame::Oversize { resynced: true });
                }
                return Ok(Frame::Line(buf));
            }
            None => {
                buf.extend_from_slice(available);
                reader.consume(chunk_len);
                if buf.len() > FRAME_CAP {
                    return drain_frame(reader);
                }
            }
        }
    }
}

/// Discard the rest of an oversized line without buffering it: resync to the
/// next newline when it arrives within `DRAIN_CAP`, otherwise report
/// `resynced: false` so the caller closes the session rather than draining
/// an endless newline-free flood.
fn drain_frame<R: BufRead>(reader: &mut R) -> std::io::Result<Frame> {
    let mut skipped: usize = 0;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            // EOF terminates the frame: emit the error, then the next read
            // sees clean EOF and closes the session.
            return Ok(Frame::Oversize { resynced: true });
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                reader.consume(pos + 1);
                return Ok(Frame::Oversize { resynced: true });
            }
            None => {
                let n = available.len();
                reader.consume(n);
                skipped += n;
                if skipped >= DRAIN_CAP {
                    return Ok(Frame::Oversize { resynced: false });
                }
            }
        }
    }
}

/// Serve the adapter: read JSON-RPC lines from `stdin`, write responses to
/// `out`, until EOF. The token (if any) authenticates every broker call;
/// without one the broker denies each tool call closed — the handshake still
/// answers, since it never touches the broker.
pub fn serve(
    socket: &Path,
    token: Option<String>,
    stdin: &mut dyn std::io::Read,
    out: &mut dyn Write,
) -> Result<(), VaultError> {
    let auth = match token {
        Some(t) => Auth::AgentToken(t),
        None => Auth::None,
    };
    let mut adapter = Adapter {
        socket,
        auth: &auth,
        leases: HashMap::new(),
    };
    let mut reader = std::io::BufReader::new(stdin);
    loop {
        match read_frame(&mut reader)? {
            Frame::Eof => return Ok(()),
            Frame::Oversize { resynced } => {
                let resp = rpc_error(
                    Value::Null,
                    -32700,
                    "parse error: message too large".to_string(),
                );
                writeln!(out, "{resp}")?;
                out.flush()?;
                if !resynced {
                    // The oversized line never terminated within the drain
                    // budget: close cleanly rather than draining forever.
                    return Ok(());
                }
                continue;
            }
            Frame::Line(raw) => {
                // Bytes first, UTF-8 second: one bad frame is one `-32700`
                // (like malformed JSON below), never a dead session (N3).
                let line = match String::from_utf8(raw) {
                    Ok(s) => s,
                    Err(_) => {
                        let resp = rpc_error(Value::Null, -32700, "parse error".to_string());
                        writeln!(out, "{resp}")?;
                        out.flush()?;
                        continue;
                    }
                };
                if line.trim().is_empty() {
                    continue;
                }
                let msg: Value = match serde_json::from_str(&line) {
                    Ok(m) => m,
                    Err(_) => {
                        let resp = rpc_error(Value::Null, -32700, "parse error".to_string());
                        writeln!(out, "{resp}")?;
                        out.flush()?;
                        continue;
                    }
                };
                if let Some(resp) = handle_message(&mut adapter, &msg) {
                    let text = serde_json::to_string(&resp)
                        .map_err(|e| VaultError::Protocol(e.to_string()))?;
                    writeln!(out, "{text}")?;
                    out.flush()?;
                }
            }
        }
    }
}
