//! Dashboard backend: pure logic (Tauri-free) + thin Tauri command wrappers.
//!
//! Layout: `backend.rs` holds ALL behavior (state machine, error mapping,
//! allowlist) with zero `tauri` dependency so it is unit-testable without a
//! GUI. `main.rs` holds only the thirty `#[tauri::command]` wrappers.

pub mod backend;

#[cfg(test)]
mod tests;
