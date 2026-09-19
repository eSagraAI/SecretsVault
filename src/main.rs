//! `svault` binary.
//!
//! Phase 1 modes: human CLI (`init`, `status`, `unlock`, `lock`).
//! Later phases add the broker daemon and `mcp-serve` (MCP stdio adapter).

fn main() {
    // Full argv including argv[0]: clap uses the first item as the binary name.
    let args: Vec<String> = std::env::args().collect();
    let mut stdin = std::io::stdin();
    let code = svault::cli::run(
        &args,
        &mut stdin,
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    );
    std::process::exit(code);
}
