pub mod client;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

pub struct TestHarness {
    pub grpc_addr: SocketAddr,
    pub http_addr: SocketAddr,
}

/// Absolute path to `docker/docker-compose.yml` in the workspace (this crate lives at `tests/integration`).
pub fn compose_file_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docker/docker-compose.yml")
}

/// Returns true if `docker compose ps` reports at least one running container for the Agent FirewallKit stack.
///
/// Requires the Docker CLI on `PATH`. This checks the infra services only (Postgres, Redis, NATS,
/// ClickHouse); it does not ensure `agentfirewall-server` is running unless that service is added to compose.
pub async fn check_compose_running() -> bool {
    let compose = compose_file_path();
    if !compose.is_file() {
        return false;
    }
    let output = tokio::process::Command::new("docker")
        .args([
            "compose",
            "-f",
            compose.to_string_lossy().as_ref(),
            "ps",
            "-q",
            "--status",
            "running",
        ])
        .output()
        .await;
    match output {
        Ok(out) => !out.stdout.is_empty(),
        Err(_) => false,
    }
}

/// Starts the Compose stack in detached mode (`docker compose up -d`).
///
/// The returned [`Child`] completes when `docker compose` finishes scheduling containers (not when
/// containers exit). Use [`compose_down`] for teardown.
pub fn compose_up() -> Child {
    let compose = compose_file_path();
    Command::new("docker")
        .args([
            "compose",
            "-f",
            compose.to_string_lossy().as_ref(),
            "up",
            "-d",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|e| panic!("docker compose up failed to spawn: {e}"))
}

/// Stops and removes containers for the stack (`docker compose down`).
pub fn compose_down() {
    let compose = compose_file_path();
    if !compose.is_file() {
        return;
    }
    let _ = Command::new("docker")
        .args([
            "compose",
            "-f",
            compose.to_string_lossy().as_ref(),
            "down",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status();
}

impl TestHarness {
    pub async fn wait_for_ready(addr: SocketAddr, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        let url = format!("http://{addr}/healthz");
        while start.elapsed() < timeout {
            if let Ok(resp) = reqwest::get(&url).await {
                if resp.status().is_success() {
                    return true;
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        false
    }
}
