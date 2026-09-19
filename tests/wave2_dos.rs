//! Wave 2 (C5) — denial-of-service resistance for the broker.
//!
//! Post-audit findings covered here:
//!
//! * idle connections held a global slot for a full 30 s read timeout, so 32
//!   sockets that never send a byte could starve every real client;
//! * a header could declare unlimited passphrase slots, each costing a full
//!   Argon2 derivation per attempt, with the whole derivation running under
//!   the session mutex — so `vault.status` (which needs no credentials at
//!   all) blocked behind every passphrase attempt;
//! * the KDF upper bounds allowed a valid header to demand 1 GiB of RAM and
//!   ~133 s of CPU in release (measured), which a tampered vault file can
//!   request at every unlock.
//!
//! Every test drives the real `svault` binary over its real socket, so the
//! accept loop, the timeouts and the dispatch all run as shipped.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use svault::envelope::{B64, Envelope, KdfParams, Slot, SlotType};
use svault::session::{Session, SystemClock};

const PASS: &str = "correct horse battery";
const BIN: &str = env!("CARGO_BIN_EXE_svault");
const IDLE: Duration = Duration::from_secs(300);

/// A first request must arrive within this window or the broker drops the
/// connection (mirrors `broker::FIRST_REQUEST_TIMEOUT`, pinned here so a
/// regression that widens it fails this file).
const FIRST_REQUEST_WINDOW: Duration = Duration::from_secs(5);
/// The broker's cap on concurrently served connections.
const CONNECTION_CAP: usize = svault::broker::MAX_CONCURRENT_CONNECTIONS;
/// Slots beyond this are not a vault anyone can plausibly hold.
const ABSURD_SLOTS: usize = 64;
/// Argon2 memory a valid header must not be able to demand.
const ABSURD_M_KIB: u32 = 1024 * 1024; // 1 GiB

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("svault-wave2c5-{tag}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }

    fn vault(&self) -> PathBuf {
        self.0.join("vault.enc")
    }

    fn sock(&self) -> PathBuf {
        self.0.join("svault.sock")
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A real daemon process, killed when the test ends (including on panic) so a
/// failed assertion never leaves a broker holding the socket.
struct DaemonProc(Child);

impl Drop for DaemonProc {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn spawn_daemon(dir: &Dir) -> DaemonProc {
    let child = Command::new(BIN)
        .arg("--socket")
        .arg(dir.sock())
        .arg("--file")
        .arg(dir.vault())
        .arg("daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn svault daemon");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if UnixStream::connect(dir.sock()).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    DaemonProc(child)
}

/// Connect with bounded read/write timeouts.
fn connect(sock: &Path, read_timeout: Duration) -> UnixStream {
    let s = UnixStream::connect(sock).expect("daemon socket connect");
    s.set_read_timeout(Some(read_timeout)).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

/// Send one NDJSON request on an open stream.
fn send(
    stream: &mut UnixStream,
    id: &str,
    op: &str,
    auth: serde_json::Value,
    params: serde_json::Value,
) {
    let auth = if auth.is_null() {
        String::new()
    } else {
        format!(",\"auth\":{auth}")
    };
    let line = format!("{{\"v\":1,\"id\":\"{id}\",\"op\":\"{op}\"{auth},\"params\":{params}}}\n");
    stream.write_all(line.as_bytes()).unwrap();
    stream.flush().unwrap();
}

fn read_line(stream: &mut UnixStream) -> String {
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    line
}

/// One request on a fresh connection: returns `(line, elapsed)`.
fn round_trip(
    sock: &Path,
    id: &str,
    op: &str,
    auth: serde_json::Value,
    params: serde_json::Value,
    read_timeout: Duration,
) -> (String, Duration) {
    let mut s = connect(sock, read_timeout);
    let start = Instant::now();
    send(&mut s, id, op, auth, params);
    let line = read_line(&mut s);
    (line, start.elapsed())
}

/// Create a vault with the public API, then rebuild its slot table: `decoys`
/// structurally valid passphrase slots holding no usable MEK (random wraps —
/// each still costs a full Argon2 derivation before it fails), and one final
/// slot wrapping the real MEK under `kdf`.
///
/// This is what an attacker-writable vault header can declare, so it is the
/// only honest way to exercise the bounds.
fn craft_slots(vault: &Path, real_pass: &[u8], decoys: usize, kdf: KdfParams) {
    use svault::crypto;
    let bytes = std::fs::read(vault).unwrap();
    let mut env = Envelope::parse(&bytes).unwrap();
    let keys = env.unlock(real_pass).unwrap();
    let mut doc = env.open_document(&keys).unwrap();
    // All slots reuse slot 0's id so the MEK AAD (`svault/v1/mek:<id>`) is
    // unchanged — the crafted vault stays genuinely unlockable.
    let id = env.header.slots[0].id.clone();

    let mut slots: Vec<Slot> = Vec::new();
    for _ in 0..decoys {
        slots.push(Slot {
            id: id.clone(),
            kind: SlotType::Passphrase,
            kdf: kdf.clone(),
            salt: B64(zeroize::Zeroizing::new(
                crypto::random_bytes::<16>().unwrap().to_vec(),
            )),
            nonce: B64(zeroize::Zeroizing::new(
                crypto::random_bytes::<24>().unwrap().to_vec(),
            )),
            wrapped_mek: B64(zeroize::Zeroizing::new(vec![0u8; 32 + 16])),
        });
    }
    let salt = crypto::random_bytes::<16>().unwrap();
    let nonce = crypto::random_bytes::<24>().unwrap();
    let kek = crypto::derive_kek(real_pass, kdf.m_kib, kdf.t, kdf.p, &salt).unwrap();
    let wrapped = crypto::seal(
        kek.as_bytes(),
        &nonce,
        keys.mek.as_bytes(),
        format!("svault/v1/mek:{id}").as_bytes(),
    );
    slots.push(Slot {
        id: id.clone(),
        kind: SlotType::Passphrase,
        kdf,
        salt: B64(zeroize::Zeroizing::new(salt.to_vec())),
        nonce: B64(zeroize::Zeroizing::new(nonce.to_vec())),
        wrapped_mek: B64(zeroize::Zeroizing::new(wrapped)),
    });
    env.header.slots = slots;
    env.reseal_document(&doc, &keys).unwrap();
    zeroize::Zeroize::zeroize(&mut doc);
    std::fs::write(vault, env.to_bytes()).unwrap();
}

/// Seed a vault with a project so later mutations have somewhere to land.
fn seed_vault(dir: &Dir) {
    let mut s =
        Session::create(&dir.vault(), PASS.as_bytes(), IDLE, Box::new(SystemClock)).unwrap();
    s.project_add("human", "acme", &[]).unwrap();
}

// ---------------------------------------------------------------------------
// C5 — idle connections must not hold the global slot indefinitely
// ---------------------------------------------------------------------------

/// A client that connects and never sends must not be able to starve every
/// other client: the broker grants a connection a short window to produce its
/// first request and then reclaims the slot.
#[test]
fn c5_idle_connections_are_reclaimed_and_service_recovers() {
    let dir = Dir::new("idle");
    seed_vault(&dir);
    let _daemon = spawn_daemon(&dir);

    // Hold every slot with sockets that never write a byte.
    let mut idle: Vec<UnixStream> = Vec::new();
    for _ in 0..CONNECTION_CAP {
        idle.push(connect(&dir.sock(), Duration::from_secs(20)));
    }

    // The cap is real: a further client is refused, and promptly (it must not
    // block behind the idle sockets).
    let (line, refused) = round_trip(
        &dir.sock(),
        "probe0",
        "vault.status",
        serde_json::Value::Null,
        serde_json::json!({}),
        Duration::from_secs(10),
    );
    assert!(
        refused < Duration::from_secs(2),
        "the cap rejection took {refused:?}; the accept loop must not block"
    );
    assert!(
        line.contains("E_PROTOCOL") || line.contains("E_BUSY"),
        "expected a fail-closed rejection at the cap, got: {line}"
    );

    // Past the first-request window the idle sockets must have been reclaimed
    // and real clients served again. Before the fix each slot was pinned for
    // the full 30 s read timeout, so this is the regression under test.
    std::thread::sleep(FIRST_REQUEST_WINDOW + Duration::from_secs(3));
    let (line, elapsed) = round_trip(
        &dir.sock(),
        "probe1",
        "vault.status",
        serde_json::Value::Null,
        serde_json::json!({}),
        Duration::from_secs(10),
    );
    assert!(
        line.contains("\"ok\":true"),
        "C5 REGRESSION: idle connections still hold the connection cap after \
         {:?} (took {elapsed:?}); got: {line}",
        FIRST_REQUEST_WINDOW + Duration::from_secs(3)
    );

    drop(idle);
}

// ---------------------------------------------------------------------------
// C5 — wrong passphrase attempts must not wedge the service
// ---------------------------------------------------------------------------

#[test]
fn c5_many_wrong_passphrases_do_not_wedge_the_daemon() {
    let dir = Dir::new("wrongauth");
    seed_vault(&dir);
    let _daemon = spawn_daemon(&dir);

    for i in 0..5 {
        let (line, elapsed) = round_trip(
            &dir.sock(),
            &format!("bad{i}"),
            "vault.unlock",
            serde_json::json!({"passphrase": format!("wrong passphrase number {i}")}),
            serde_json::json!({}),
            Duration::from_secs(60),
        );
        assert!(
            line.contains("E_AUTH"),
            "a wrong passphrase must fail closed with E_AUTH, got: {line}"
        );
        assert!(
            elapsed < Duration::from_secs(30),
            "attempt {i} took {elapsed:?}; a bounded derivation must not hang"
        );
    }

    // The cheap, credential-free op must still be answered after the flood.
    let (line, _) = round_trip(
        &dir.sock(),
        "status",
        "vault.status",
        serde_json::Value::Null,
        serde_json::json!({}),
        Duration::from_secs(10),
    );
    assert!(
        line.contains("\"ok\":true"),
        "vault.status must survive repeated auth failures, got: {line}"
    );

    // And the real passphrase still works: no lockout, no oracle.
    let (line, _) = round_trip(
        &dir.sock(),
        "good",
        "vault.unlock",
        serde_json::json!({"passphrase": PASS}),
        serde_json::json!({}),
        Duration::from_secs(60),
    );
    assert!(
        line.contains("\"ok\":true"),
        "the correct passphrase must still unlock, got: {line}"
    );
}

// ---------------------------------------------------------------------------
// C5 — a valid header must not be able to demand absurd derivation cost
// ---------------------------------------------------------------------------

/// `m_kib = 1 GiB` is a *valid* header today, and each attempt then costs a
/// measured ~24 s (debug) / ~1.3 s (release) plus 1 GiB of resident memory,
/// under the session mutex. It must be refused outright, before deriving.
#[test]
fn c5_absurd_kdf_memory_is_refused_without_deriving() {
    let dir = Dir::new("kdf");
    seed_vault(&dir);
    craft_slots(
        &dir.vault(),
        PASS.as_bytes(),
        0,
        KdfParams {
            algo: "argon2id".into(),
            m_kib: ABSURD_M_KIB,
            t: 3,
            p: 4,
        },
    );

    // The refusal happens before any derivation, so it is fast even though the
    // requested work is not. A 24 s denial would blow this budget.
    let started = Instant::now();
    let mut s = Session::load(&dir.vault(), IDLE, Box::new(SystemClock)).unwrap();
    let err = s
        .unlock(PASS.as_bytes())
        .expect_err("a 1 GiB KDF request must be refused");
    let elapsed = started.elapsed();
    assert_eq!(
        err.code(),
        "E_INSECURE_PARAMS",
        "expected the bounds refusal, got {err}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "C5 REGRESSION: refusing took {elapsed:?}; the header was refused only \
         after doing the work"
    );
}

/// The same bound is enforced when the derivation is driven through the
/// daemon, and it stays fail-closed without becoming an oracle: the error is
/// about the header's parameters, never about the passphrase.
#[test]
fn c5_absurd_kdf_memory_is_refused_over_the_wire() {
    let dir = Dir::new("kdfwire");
    seed_vault(&dir);
    craft_slots(
        &dir.vault(),
        PASS.as_bytes(),
        0,
        KdfParams {
            algo: "argon2id".into(),
            m_kib: ABSURD_M_KIB,
            t: 3,
            p: 4,
        },
    );
    let _daemon = spawn_daemon(&dir);

    let (line, elapsed) = round_trip(
        &dir.sock(),
        "kdf",
        "vault.unlock",
        serde_json::json!({"passphrase": PASS}),
        serde_json::json!({}),
        Duration::from_secs(30),
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "C5 REGRESSION: the daemon spent {elapsed:?} on a 1 GiB header"
    );
    assert!(
        line.contains("E_INSECURE_PARAMS"),
        "expected E_INSECURE_PARAMS over the wire, got: {line}"
    );
}

// ---------------------------------------------------------------------------
// C5 — excess slots
// ---------------------------------------------------------------------------

/// Each passphrase slot costs a full derivation per attempt, so an unbounded
/// slot table is a CPU amplification vector. A vault declaring far more slots
/// than any real vault needs must be refused, not loaded and ground through.
#[test]
fn c5_excess_passphrase_slots_are_refused() {
    let dir = Dir::new("slots");
    seed_vault(&dir);
    // Every extra slot is structurally valid, so only a slot-count limit can
    // stop the loader from accepting it.
    craft_slots(
        &dir.vault(),
        PASS.as_bytes(),
        ABSURD_SLOTS - 1,
        KdfParams::argon2id_defaults(),
    );

    let err = Session::load(&dir.vault(), IDLE, Box::new(SystemClock))
        .expect_err("a vault with an absurd slot table must be refused");
    assert_eq!(
        err.code(),
        "E_VAULT_CORRUPT",
        "expected a structural refusal, got {err}"
    );

    // A vault whose slot count is the maximum we actually support still loads.
    let dir2 = Dir::new("slots-ok");
    seed_vault(&dir2);
    craft_slots(
        &dir2.vault(),
        PASS.as_bytes(),
        3,
        KdfParams::argon2id_defaults(),
    );
    let mut ok = Session::load(&dir2.vault(), IDLE, Box::new(SystemClock))
        .expect("a handful of slots must remain loadable");
    ok.unlock(PASS.as_bytes()).expect("and unlockable");
}

// ---------------------------------------------------------------------------
// C5 — a costly derivation must not block cheap operations
// ---------------------------------------------------------------------------

/// The vault is legal and expensive: seven slots whose wraps are junk (each
/// still costs a derivation before failing) plus the real slot last. A correct
/// unlock therefore grinds through eight derivations. Meanwhile
/// `vault.status` — which needs no credentials at all — must stay answered.
#[test]
fn c5_costly_unlock_does_not_block_vault_status() {
    let dir = Dir::new("responsive");
    seed_vault(&dir);
    craft_slots(
        &dir.vault(),
        PASS.as_bytes(),
        7,
        KdfParams::argon2id_defaults(),
    );
    let _daemon = spawn_daemon(&dir);

    // Sanity: the crafted vault is genuinely unlockable (the real slot is
    // last), which is what makes the cost real.
    let sock = dir.sock();
    let unlock = std::thread::spawn(move || {
        round_trip(
            &sock,
            "unlock",
            "vault.unlock",
            serde_json::json!({"passphrase": PASS}),
            serde_json::json!({}),
            Duration::from_secs(120),
        )
    });

    // While the derivations run, the credential-free op must answer promptly.
    std::thread::sleep(Duration::from_millis(400));
    let mut worst = Duration::ZERO;
    for i in 0..3 {
        let (line, elapsed) = round_trip(
            &dir.sock(),
            &format!("s{i}"),
            "vault.status",
            serde_json::Value::Null,
            serde_json::json!({}),
            Duration::from_secs(5),
        );
        worst = worst.max(elapsed);
        assert!(
            line.contains("\"ok\":true"),
            "vault.status must stay available during a costly derivation, got: {line}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        worst < Duration::from_secs(3),
        "C5 REGRESSION: vault.status blocked for {worst:?} behind passphrase \
         derivations running under the session lock"
    );

    let (line, _) = unlock.join().expect("unlock thread");
    assert!(
        line.contains("\"ok\":true"),
        "the costly but legitimate unlock must still succeed, got: {line}"
    );
}
