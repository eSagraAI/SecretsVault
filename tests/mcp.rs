use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use serde_json::{Value, json};
use svault::broker::{Daemon, DaemonConfig};
use svault::wire::{AuthField, Request, VERSION};

const PASS: &str = "correct horse battery";
const TRAP: &str = "mcp-TRAP-secret-value";

fn human(id: &str, op: &str, params: Value) -> Request {
    Request {
        v: VERSION,
        id: id.into(),
        op: op.into(),
        auth: Some(AuthField {
            token: None,
            passphrase: Some(PASS.into()),
            session: None,
        }),
        params,
    }
}

fn agent(id: &str, op: &str, token: &str, params: Value) -> Request {
    Request {
        v: VERSION,
        id: id.into(),
        op: op.into(),
        auth: Some(AuthField {
            token: Some(token.into()),
            passphrase: None,
            session: None,
        }),
        params,
    }
}

/// A temporary directory removed on drop, panics included (L3: a test run must
/// leave no vault, socket or token behind).
struct TempRoot(PathBuf);

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct DaemonFixture {
    daemon: std::sync::Arc<Daemon>,
    token: String,
    vault_path: PathBuf,
    socket: PathBuf,
    _root: TempRoot,
}

impl Drop for DaemonFixture {
    fn drop(&mut self) {
        // Pin hygiene: trust for a dead socket must not leak into the next test.
        if let Ok(pin) = svault::broker_identity::pin_path(&self.socket) {
            let _ = std::fs::remove_file(pin);
        }
    }
}

fn setup_daemon() -> DaemonFixture {
    let root = std::env::temp_dir().join(format!(
        "svault-mcp-{}-{}",
        std::process::id(),
        svault::crypto::hex(&svault::crypto::random_bytes::<8>().unwrap())
    ));
    std::fs::create_dir_all(&root).unwrap();
    let vault_path = root.join("vault.enc");
    let socket = root.join("svault.sock");
    let daemon = std::sync::Arc::new(
        Daemon::new(DaemonConfig {
            socket_path: socket.clone(),
            vault_path: vault_path.clone(),
            idle_lock: Duration::from_secs(60),
        })
        .unwrap(),
    );
    assert!(
        daemon
            .handle_request(human("1", "vault.create", json!({})))
            .ok
    );
    assert!(
        daemon
            .handle_request(human("2", "project.add", json!({"name":"acme"})))
            .ok
    );
    assert!(
        daemon
            .handle_request(human(
                "3",
                "secret.set",
                json!({"project":"acme","key":"API_KEY","value":TRAP}),
            ))
            .ok
    );
    let added = daemon.handle_request(human("4", "agents.add", json!({"name":"bot"})));
    assert!(added.ok, "{:?}", added.error);
    let token = added.result.unwrap()["token"].as_str().unwrap().to_owned();
    assert!(
        daemon
            .handle_request(human(
                "5",
                "grants.grant",
                json!({"agent":"bot","project":"acme","ops":"read,reveal"}),
            ))
            .ok
    );
    let srv = std::sync::Arc::clone(&daemon);
    std::thread::spawn(move || {
        let _ = srv.serve();
    });
    DaemonFixture {
        daemon,
        token,
        vault_path,
        socket,
        _root: TempRoot(root),
    }
}

/// N1 pin bootstrap for the harness: the test acts as the human out-of-band
/// channel (reads the daemon's public key in-process) and writes the pin
/// DIRECTLY — never via argv. Without this, every tool call fails closed
/// with E_BROKER_UNTRUSTED, correctly: MCP contexts may reuse a pin but
/// never create one.
fn pin_bootstrap(fix: &DaemonFixture) {
    svault::broker_identity::store_pin(&fix.socket, &fix.daemon.broker_public_key())
        .expect("test pin bootstrap");
}

struct Mcp {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: i64,
    transcript: String,
}

impl Mcp {
    fn spawn(socket: &std::path::Path, token: &str, root: &std::path::Path) -> Self {
        let token_file = root.join("bot.token");
        write_token_0600(&token_file, token);
        // L3: the harness must not leave a live capability world-readable.
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&token_file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "harness token file must be 0600, got {mode:o}");
        }
        let mut child = Command::new(env!("CARGO_BIN_EXE_svault"))
            .arg("--socket")
            .arg(socket)
            .arg("--token-file")
            .arg(&token_file)
            .arg("mcp-serve")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn svault mcp-serve");
        let stdin = child.stdin.take().expect("mcp stdin");
        let stdout = BufReader::new(child.stdout.take().expect("mcp stdout"));
        Self {
            child,
            stdin,
            stdout,
            next_id: 1,
            transcript: String::new(),
        }
    }

    fn roundtrip(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});
        writeln!(self.stdin, "{msg}").unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        assert!(!line.is_empty(), "mcp-serve closed stdio on {method}");
        self.transcript.push_str(&line);
        let resp: Value = serde_json::from_str(&line).expect("mcp response is JSON");
        assert_eq!(resp["id"], id, "json-rpc id echoed for {method}");
        resp
    }

    fn call(&mut self, tool: &str, args: Value) -> Value {
        self.roundtrip("tools/call", json!({"name":tool,"arguments":args}))
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// L3: a token file is a live capability; it must be 0600 from creation, never
/// left world-readable for the process umask to decide.
fn write_token_0600(path: &std::path::Path, token: &str) {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("create token file");
    f.write_all(token.as_bytes()).expect("write token");
    f.sync_all().expect("sync token");
}

fn ok_text(resp: &Value) -> Value {
    let text = ok_raw_text(resp);
    assert!(
        !text.contains(TRAP),
        "broker value leaked into mcp text: {text}"
    );
    serde_json::from_str(&text).expect("tool text is broker JSON")
}

fn ok_secret_text(resp: &Value) -> Value {
    serde_json::from_str(&ok_raw_text(resp)).expect("tool text is broker JSON")
}

fn ok_raw_text(resp: &Value) -> String {
    let result = resp.get("result").expect("tools/call has result");
    assert!(
        result.get("isError").is_none(),
        "expected success, got {resp}"
    );
    result["content"][0]["text"]
        .as_str()
        .expect("text content")
        .to_owned()
}

fn err_detail(resp: &Value) -> Value {
    let result = resp
        .get("result")
        .expect("broker failure is result+isError");
    assert_eq!(result["isError"], true, "expected isError, got {resp}");
    let text = result["content"][0]["text"]
        .as_str()
        .expect("text content")
        .to_owned();
    assert!(!text.contains(TRAP), "secret leaked into mcp error: {text}");
    serde_json::from_str(&text).expect("error text is broker JSON")
}

#[test]
fn mcp_adapter_exposes_exactly_six_agent_tools() {
    let fix = setup_daemon();
    pin_bootstrap(&fix);
    let mut mcp = Mcp::spawn(&fix.socket, &fix.token, &fix._root.0);

    // initialize answers without touching the broker.
    let init = mcp.roundtrip("initialize", json!({"protocolVersion":"2024-11-05"}));
    assert_eq!(init["result"]["serverInfo"]["name"], "svault");
    assert!(init["result"]["capabilities"]["tools"].is_object());

    // tools/list: exactly the six agent tools, no human-only or run tools.
    let listed = mcp.roundtrip("tools/list", json!({}));
    let tools = listed["result"]["tools"]
        .as_array()
        .expect("tools array")
        .to_owned();
    let mut names: Vec<String> = tools
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "approval_status",
            "inject_file",
            "lease_create",
            "lease_revoke",
            "list_secrets",
            "reveal"
        ]
    );
    for human_only in [
        "approvals.approve",
        "approvals.deny",
        "approvals.pending",
        "agents.add",
        "agents.revoke",
        "agents.list",
        "grants.grant",
        "grants.revoke",
        "grants.list",
        "secret.set",
        "secret.delete",
        "project.add",
        "project.list",
        "audit.show",
        "audit.verify",
        "run_with_secrets",
        "run_signal",
        "vault.unlock",
        "vault.lock",
    ] {
        assert!(
            !names.iter().any(|n| n == human_only),
            "human-only tool exposed: {human_only}"
        );
    }
    assert!(!serde_json::to_string(&listed).unwrap().contains(TRAP));

    // Human-only tools are absent, never broker errors: unknown-tool, not isError.
    for unknown in [
        "approvals.approve",
        "approvals.deny",
        "run_with_secrets",
        "audit.show",
    ] {
        let resp = mcp.call(unknown, json!({}));
        assert!(
            resp.get("result").is_none(),
            "absent tool must not forward: {unknown}"
        );
        assert_eq!(
            resp["error"]["code"], -32602,
            "unknown tool {unknown}: {resp}"
        );
    }

    // Agent tool forwarding: list_secrets returns names only.
    let body = ok_text(&mcp.call("list_secrets", json!({"project":"acme"})));
    let blob = serde_json::to_string(&body).unwrap();
    assert!(blob.contains("API_KEY"), "{blob}");
    assert!(!blob.contains(TRAP));

    // reveal without approval_id surfaces E_APPROVAL_PENDING + pointers, nonblocking.
    let pending = err_detail(&mcp.call("reveal", json!({"project":"acme","key":"API_KEY"})));
    assert_eq!(pending["code"], "E_APPROVAL_PENDING");
    let approval_id = pending["data"]["approval_id"]
        .as_str()
        .expect("approval_id")
        .to_owned();
    assert!(pending["data"]["expires_in"].as_u64().unwrap() > 0);

    // approval_status polls the pending approval.
    let status = ok_text(&mcp.call("approval_status", json!({"approval_id":approval_id})));
    assert_eq!(status["status"], "pending");
    assert_eq!(status["project"], "acme");
    assert_eq!(status["key"], "API_KEY");

    // Human approves over the broker wire; the agent claims the value once via MCP.
    assert!(
        fix.daemon
            .handle_request(human(
                "6",
                "approvals.approve",
                json!({"approval_id":approval_id}),
            ))
            .ok
    );
    let claim = ok_secret_text(&mcp.call(
        "reveal",
        json!({"project":"acme","key":"API_KEY","approval_id":approval_id}),
    ));
    assert_eq!(claim["value"], TRAP);
    let again = err_detail(&mcp.call(
        "reveal",
        json!({"project":"acme","key":"API_KEY","approval_id":approval_id}),
    ));
    assert_eq!(again["code"], "E_APPROVAL_CONSUMED");

    // Leases over MCP: the adapter keeps the credential, the model sees only
    // the public handle and the display prefix.
    let lease = ok_text(&mcp.call(
        "lease_create",
        json!({"project":"acme","ops":"read","ttl_secs":60}),
    ));
    let lease_id = lease["lease_id"].as_str().expect("lease_id").to_owned();
    assert!(
        lease.get("lease_credential").is_none(),
        "credential must never reach the model: {lease}"
    );
    let prefix = lease["lease_prefix"]
        .as_str()
        .expect("lease_prefix")
        .to_owned();
    assert_eq!(prefix.len(), 8);
    let used = ok_text(&mcp.call(
        "list_secrets",
        json!({"project":"acme","lease_id":lease_id}),
    ));
    assert!(serde_json::to_string(&used).unwrap().contains("API_KEY"));
    // Escalation through MCP is still E_PERMISSION.
    let escalate = err_detail(&mcp.call(
        "lease_create",
        json!({"project":"acme","ops":"run","ttl_secs":60}),
    ));
    assert_eq!(escalate["code"], "E_PERMISSION");
    // An unknown handle fails closed rather than widening to the full grant.
    let bogus = err_detail(&mcp.call(
        "list_secrets",
        json!({"project":"acme","lease_id":"deadbeefdeadbeef"}),
    ));
    assert_eq!(bogus["code"], "E_LEASE_EXPIRED");
    let revoked = mcp.call("lease_revoke", json!({"lease_id":lease_id}));
    assert!(revoked.get("result").is_some(), "revoke answers: {revoked}");
    let expired = err_detail(&mcp.call(
        "list_secrets",
        json!({"project":"acme","lease_id":lease_id}),
    ));
    assert_eq!(expired["code"], "E_LEASE_EXPIRED");

    // No secret value anywhere except the single intentional claim body, and
    // no lease credential anywhere on the MCP wire at all.
    assert!(
        !mcp.transcript.matches(TRAP).nth(1).is_some(),
        "value appears more than once on mcp stdio"
    );
    let audit =
        std::fs::read_to_string(fix.vault_path.with_file_name("audit.jsonl")).unwrap_or_default();
    assert!(!audit.contains(TRAP));

    // The credential the broker minted is known to this test only because it
    // reached the adapter; it must exist nowhere in the transcript or the
    // audit log. Re-mint one over the broker wire and prove the same, so the
    // assertion does not depend on adapter internals.
    let minted = fix
        .daemon
        .handle_request(agent(
            "L9",
            "lease.create",
            &fix.token,
            json!({"project":"acme","ops":"read","ttl_secs":60}),
        ))
        .result
        .expect("lease.create ok")["lease_credential"]
        .as_str()
        .expect("credential")
        .to_owned();
    assert_eq!(minted.len(), 43, "256-bit base64url credential");
    assert!(!mcp.transcript.contains(&minted), "credential on mcp wire");
    assert!(!audit.contains(&minted), "credential in audit");
}

/// H3 — the adapter must never accept a lease *credential* from the caller.
///
/// `lease_id` is the only lease input a model may name: the adapter maps it to
/// the credential it holds. A caller-supplied `lease` would put a live
/// capability on the wire (and into the transcript/logs), and would let the
/// model present a credential the adapter never issued — so it must be
/// refused, not forwarded.
#[test]
fn h3_caller_supplied_lease_credential_is_refused() {
    let fix = setup_daemon();
    pin_bootstrap(&fix);
    let mut mcp = Mcp::spawn(&fix.socket, &fix.token, &fix._root.0);

    // A credential the broker really minted, but which this adapter never saw.
    let foreign = fix
        .daemon
        .handle_request(agent(
            "L1",
            "lease.create",
            &fix.token,
            json!({"project":"acme","ops":"read","ttl_secs":60}),
        ))
        .result
        .expect("lease.create ok")["lease_credential"]
        .as_str()
        .expect("credential")
        .to_owned();

    for (tool, args) in [
        ("list_secrets", json!({"project":"acme","lease":foreign})),
        (
            "inject_file",
            json!({"project":"acme","path":".env","lease":foreign}),
        ),
        (
            "reveal",
            json!({"project":"acme","key":"API_KEY","lease":foreign}),
        ),
    ] {
        let resp = mcp.call(tool, args);
        let detail = err_detail(&resp);
        assert_eq!(
            detail["code"], "E_INVALID_INPUT",
            "H3 REGRESSION: {tool} must refuse a caller-supplied credential: {resp}"
        );
    }

    // The capability must not have crossed the adapter at all.
    assert!(
        !mcp.transcript.contains(&foreign),
        "H3 REGRESSION: a caller-supplied credential reached the MCP wire/logs"
    );
}
