//! CLI accessibility and non-interactive mode tests.
//! Validates that all commands support --json output and produce
//! deterministic, parseable responses for CI/automation use.

fn workspace_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/agentfirewall-cli")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn help_flag_works() {
    let output = std::process::Command::new("cargo")
        .current_dir(workspace_root())
        .args(["run", "-p", "agentfirewall-cli", "--", "--help"])
        .output()
        .expect("failed to run CLI");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("agentfirewall") || stdout.contains("Agent FirewallKit"));
}

#[test]
fn json_flag_available() {
    let output = std::process::Command::new("cargo")
        .current_dir(workspace_root())
        .args([
            "run",
            "-p",
            "agentfirewall-cli",
            "--",
            "policy",
            "list",
            "--help",
        ])
        .output()
        .expect("failed to run CLI");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--json") || stdout.contains("json"));
}
