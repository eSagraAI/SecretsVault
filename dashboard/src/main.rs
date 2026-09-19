//! Tauri entry: thirty `#[tauri::command]` wrappers over [`backend`].
//! All behavior lives in `backend` (Tauri-free, unit-tested); this file only
//! adapts `State<AppState>` + IPC args to those pure functions.

use svault_dashboard_lib::backend::{self, AppState};

#[tauri::command]
fn get_status(state: tauri::State<'_, AppState>) -> Result<backend::StatusOut, backend::CmdError> {
    backend::get_status(&state)
}

#[tauri::command]
fn pin_status(
    state: tauri::State<'_, AppState>,
) -> Result<backend::PinStatusOut, backend::CmdError> {
    backend::pin_status(&state)
}

#[tauri::command]
fn probe_fingerprint(
    state: tauri::State<'_, AppState>,
) -> Result<backend::ProbeOut, backend::CmdError> {
    backend::probe_fingerprint(&state)
}

#[tauri::command(rename_all = "snake_case")]
fn unlock(
    state: tauri::State<'_, AppState>,
    passphrase: String,
) -> Result<backend::UnlockOut, backend::CmdError> {
    backend::unlock(&state, backend::UnlockIn { passphrase })
}

#[tauri::command]
fn lock(state: tauri::State<'_, AppState>) -> Result<backend::LockOut, backend::CmdError> {
    backend::lock(&state)
}

#[tauri::command]
fn health(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, backend::CmdError> {
    backend::health(&state)
}

#[tauri::command]
fn overview_refresh(
    state: tauri::State<'_, AppState>,
) -> Result<backend::OverviewOut, backend::CmdError> {
    backend::overview_refresh(&state)
}

#[tauri::command]
fn projects_list(
    state: tauri::State<'_, AppState>,
) -> Result<backend::ProjectsOut, backend::CmdError> {
    backend::projects_list(&state)
}

#[tauri::command(rename_all = "snake_case")]
fn project_add(
    state: tauri::State<'_, AppState>,
    name: String,
    paths: Vec<String>,
) -> Result<backend::AddedOut, backend::CmdError> {
    backend::project_add(&state, backend::ProjectAddIn { name, paths })
}

#[tauri::command(rename_all = "snake_case")]
fn project_remove(
    state: tauri::State<'_, AppState>,
    name: String,
) -> Result<backend::RemovedOut, backend::CmdError> {
    backend::project_remove(&state, backend::NameIn { name })
}

#[tauri::command(rename_all = "snake_case")]
fn project_path_add(
    state: tauri::State<'_, AppState>,
    name: String,
    path: String,
) -> Result<backend::AddedOut, backend::CmdError> {
    backend::project_path_add(&state, backend::ProjectPathIn { name, path })
}

#[tauri::command(rename_all = "snake_case")]
fn project_path_remove(
    state: tauri::State<'_, AppState>,
    name: String,
    path: String,
) -> Result<backend::RemovedOut, backend::CmdError> {
    backend::project_path_remove(&state, backend::ProjectPathIn { name, path })
}

#[tauri::command(rename_all = "snake_case")]
fn secrets_list(
    state: tauri::State<'_, AppState>,
    project: String,
) -> Result<backend::SecretsOut, backend::CmdError> {
    backend::secrets_list(&state, backend::SecretsListIn { project })
}

#[tauri::command(rename_all = "snake_case")]
fn secret_set(
    state: tauri::State<'_, AppState>,
    project: String,
    key: String,
    value: String,
) -> Result<backend::SecretSetOut, backend::CmdError> {
    backend::secret_set(
        &state,
        backend::SecretSetIn {
            project,
            key,
            value,
        },
    )
}

#[tauri::command(rename_all = "snake_case")]
fn secret_delete(
    state: tauri::State<'_, AppState>,
    project: String,
    key: String,
) -> Result<backend::SecretDeleteOut, backend::CmdError> {
    backend::secret_delete(&state, backend::SecretDeleteIn { project, key })
}

// NOTE (D3): the multi-word wrappers below (`agent_add`, `approval_approve`,
// `approval_deny`) carry NO `rename_all = "snake_case"`: Tauri's default
// camelCase renaming is what maps `token_path` <-> `tokenPath` and
// `approval_id` <-> `approvalId` as the frontend sends them. `snake_case`
// here would expect keys the frontend never sends.
#[tauri::command]
fn agents_list(state: tauri::State<'_, AppState>) -> Result<backend::AgentsOut, backend::CmdError> {
    backend::agents_list(&state)
}

#[tauri::command]
fn agent_add(
    state: tauri::State<'_, AppState>,
    name: String,
    token_path: Option<String>,
) -> Result<backend::AgentAddOut, backend::CmdError> {
    backend::agent_add(&state, backend::AgentAddIn { name, token_path })
}

#[tauri::command(rename_all = "snake_case")]
fn agent_revoke(
    state: tauri::State<'_, AppState>,
    name: String,
) -> Result<backend::RevokedOut, backend::CmdError> {
    backend::agent_revoke(&state, backend::NameIn { name })
}

#[tauri::command]
fn grants_list(state: tauri::State<'_, AppState>) -> Result<backend::GrantsOut, backend::CmdError> {
    backend::grants_list(&state)
}

#[tauri::command(rename_all = "snake_case")]
fn grant_set(
    state: tauri::State<'_, AppState>,
    agent: String,
    project: String,
    ops: String,
) -> Result<backend::GrantedOut, backend::CmdError> {
    backend::grant_set(
        &state,
        backend::GrantSetIn {
            agent,
            project,
            ops,
        },
    )
}

#[tauri::command(rename_all = "snake_case")]
fn grant_revoke(
    state: tauri::State<'_, AppState>,
    agent: String,
    project: String,
) -> Result<backend::RevokedOut, backend::CmdError> {
    backend::grant_revoke(&state, backend::GrantRevokeIn { agent, project })
}

#[tauri::command]
fn approvals_pending(
    state: tauri::State<'_, AppState>,
) -> Result<backend::ApprovalsOut, backend::CmdError> {
    backend::approvals_pending(&state)
}

// No `rename_all`: `approval_id` arrives as camelCase `approvalId` (see NOTE).
#[tauri::command]
fn approval_approve(
    state: tauri::State<'_, AppState>,
    approval_id: String,
) -> Result<backend::ApprovalDecisionOut, backend::CmdError> {
    backend::approval_approve(&state, backend::ApprovalDecisionIn { approval_id })
}

// No `rename_all`: `approval_id` arrives as camelCase `approvalId` (see NOTE).
#[tauri::command]
fn approval_deny(
    state: tauri::State<'_, AppState>,
    approval_id: String,
) -> Result<backend::ApprovalDecisionOut, backend::CmdError> {
    backend::approval_deny(&state, backend::ApprovalDecisionIn { approval_id })
}
// No `rename_all`: `lease_id` arrives as camelCase `leaseId` (see NOTE).
#[tauri::command]
fn lease_revoke(
    state: tauri::State<'_, AppState>,
    lease_id: String,
) -> Result<backend::LeaseRevokeOut, backend::CmdError> {
    backend::lease_revoke(&state, backend::LeaseRevokeIn { lease_id })
}

#[tauri::command(rename_all = "snake_case")]
fn reveal(
    state: tauri::State<'_, AppState>,
    project: String,
    key: String,
) -> Result<backend::RevealOut, backend::CmdError> {
    backend::reveal(&state, backend::RevealIn { project, key })
}

#[tauri::command]
fn leases_list(state: tauri::State<'_, AppState>) -> Result<backend::LeasesOut, backend::CmdError> {
    backend::leases_list(&state)
}

#[tauri::command]
fn runs_list(state: tauri::State<'_, AppState>) -> Result<backend::RunsOut, backend::CmdError> {
    backend::runs_list(&state)
}

// NOTE (D6): `before_seq` uses the DEFAULT camelCase renaming so the
// frontend's `beforeSeq` maps (see D3 NOTE above for the convention).
#[tauri::command]
fn audit_show(
    state: tauri::State<'_, AppState>,
    tail: u64,
    before_seq: Option<u64>,
) -> Result<backend::AuditShowOut, backend::CmdError> {
    backend::audit_show(&state, backend::AuditShowIn { tail, before_seq })
}

#[tauri::command]
fn audit_verify(
    state: tauri::State<'_, AppState>,
) -> Result<backend::AuditVerifyOut, backend::CmdError> {
    backend::audit_verify(&state)
}

fn main() {
    let socket = std::env::var("SVAULT_SOCKET")
        .map(std::path::PathBuf::from)
        .ok()
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| svault::broker_identity::default_socket_path().ok())
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp/svault-no-socket-configured.sock"));
    tauri::Builder::default()
        .manage(AppState::new(socket))
        .invoke_handler(tauri::generate_handler![
            get_status,
            pin_status,
            probe_fingerprint,
            unlock,
            lock,
            health,
            overview_refresh,
            projects_list,
            project_add,
            project_remove,
            project_path_add,
            project_path_remove,
            secrets_list,
            secret_set,
            secret_delete,
            agents_list,
            agent_add,
            agent_revoke,
            grants_list,
            grant_set,
            grant_revoke,
            approvals_pending,
            approval_approve,
            approval_deny,
            reveal,
            leases_list,
            lease_revoke,
            runs_list,
            audit_show,
            audit_verify
        ])
        // M1: the window is created here (not via `tauri.conf.json`, which
        // carries no `app.windows` entry): label `main` matches the
        // capability's `windows: ["main"]`. The navigation guard admits ONLY
        // the `tauri` scheme (see `backend::allow_navigation`): this project
        // has no `devUrl` and the router is hash-only, so nothing else is
        // ever legitimate.
        .setup(|app| {
            tauri::WebviewWindowBuilder::new(
                app,
                "main",
                tauri::WebviewUrl::App("index.html".into()),
            )
            .title("SecretsVault")
            .inner_size(1100.0, 720.0)
            .min_inner_size(800.0, 540.0)
            .center()
            .disable_drag_drop_handler()
            .on_navigation(|url| svault_dashboard_lib::backend::allow_navigation(url.as_str()))
            .build()?;
            Ok(())
        })
        // Close policy (v0.1.0): closing the window locks the vault and drops
        // the Rust-held session credential, then always exits. There is
        // deliberately no tray and no hide-to-tray.
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                use tauri::Manager as _;
                if let Some(state) = window.app_handle().try_state::<AppState>() {
                    // Take first so the credential is cleared from `AppState`
                    // unconditionally — including on the lock timeout path.
                    // When a session is held, lock with it; with no session
                    // there is nothing to authenticate a lock with, so call
                    // no broker op at all (a locked vault needs no lock, and
                    // an unlocked-but-sessionless app holds nothing to lock
                    // with). Never panics, never blocks on the mutex.
                    if let Some(cred) = state.take_session() {
                        let auth = svault::client::Auth::Session(cred.to_string());
                        let locked = backend::shutdown_lock(
                            &state.socket,
                            auth,
                            std::time::Duration::from_secs(3),
                        );
                        if !locked {
                            eprintln!("svault-dashboard: the vault could not be locked before exit (no confirmation from the broker); lock it with `svault lock`");
                        }
                    }
                }
                // ALWAYS exit: timeout, failure, or already-locked must all
                // still close the window. No unwrap/expect anywhere above.
                window.app_handle().exit(0);
            }
        })
        .run(tauri::generate_context!())
        .expect("failed to run SecretsVault dashboard");
}
