//! Layered configuration resolution (FR-020: env > file > programmatic > defaults).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AgentFirewallError;
use crate::types::InterventionLevel;

/// Sentinel / embedding hot-path related settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SentinelConfigSection {
    pub enabled: bool,
    pub model_id: String,
    pub stall_threshold: f32,
    pub stall_window: u32,
    pub regression_threshold: f32,
    pub intervention: InterventionLevel,
    pub max_embed_input_bytes: usize,
}

impl Default for SentinelConfigSection {
    fn default() -> Self {
        Self {
            enabled: true,
            model_id: "default-embed".into(),
            stall_threshold: 0.02,
            stall_window: 5,
            regression_threshold: 0.05,
            intervention: InterventionLevel::Warn,
            max_embed_input_bytes: 256 * 1024,
        }
    }
}

/// Witness capture and comparison limits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessConfigSection {
    pub enabled: bool,
    pub max_preimage_bytes: usize,
    pub hash_timeout_ms: u64,
}

impl Default for WitnessConfigSection {
    fn default() -> Self {
        Self {
            enabled: true,
            max_preimage_bytes: 1024 * 1024,
            hash_timeout_ms: 5000,
        }
    }
}

/// Learner / span emission client settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LearnerConfigSection {
    pub enabled: bool,
    pub endpoint: String,
    pub flush_interval_ms: u64,
    pub max_buffer_events: usize,
}

impl Default for LearnerConfigSection {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "https://localhost:8443/v1/learner".into(),
            flush_interval_ms: 250,
            max_buffer_events: 512,
        }
    }
}

/// Remote control plane connectivity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerConfigSection {
    pub url: String,
    #[serde(default)]
    pub auth_token: String,
    pub tls_verify: bool,
    #[serde(default)]
    pub ca_cert_path: Option<PathBuf>,
    #[serde(default)]
    pub client_cert_path: Option<PathBuf>,
    #[serde(default)]
    pub client_key_path: Option<PathBuf>,
}

impl Default for ServerConfigSection {
    fn default() -> Self {
        Self {
            url: "https://localhost:8443".into(),
            auth_token: String::new(),
            tls_verify: true,
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
        }
    }
}

/// Fully merged Agent FirewallKit process configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentFirewallConfig {
    #[serde(default)]
    pub sentinel: SentinelConfigSection,
    #[serde(default)]
    pub witness: WitnessConfigSection,
    #[serde(default)]
    pub learner: LearnerConfigSection,
    #[serde(default)]
    pub server: ServerConfigSection,
    #[serde(default)]
    pub standalone: bool,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
}

fn default_log_level() -> String {
    "info".into()
}

impl Default for AgentFirewallConfig {
    fn default() -> Self {
        Self {
            sentinel: SentinelConfigSection::default(),
            witness: WitnessConfigSection::default(),
            learner: LearnerConfigSection::default(),
            server: ServerConfigSection::default(),
            standalone: false,
            log_level: default_log_level(),
            tenant_id: None,
        }
    }
}

impl AgentFirewallConfig {
    /// Merges a higher-priority programmatic patch onto `self`. Only fields that differ from crate defaults are applied, so sparse patches do not clobber lower layers with implicit defaults.
    pub fn with_overrides(mut self, overrides: AgentFirewallConfig) -> AgentFirewallConfig {
        let base = AgentFirewallConfig::default();
        if overrides.log_level != base.log_level {
            self.log_level = overrides.log_level;
        }
        if overrides.standalone != base.standalone {
            self.standalone = overrides.standalone;
        }
        if overrides.tenant_id.is_some() {
            self.tenant_id = overrides.tenant_id;
        }
        if overrides.sentinel != SentinelConfigSection::default() {
            self.sentinel = overrides.sentinel;
        }
        if overrides.witness != WitnessConfigSection::default() {
            self.witness = overrides.witness;
        }
        if overrides.learner != LearnerConfigSection::default() {
            self.learner = overrides.learner;
        }
        if overrides.server != ServerConfigSection::default() {
            self.server = overrides.server;
        }
        self
    }

    fn merge_from_file_partial(&mut self, raw: &str) -> Result<(), AgentFirewallError> {
        #[derive(Deserialize)]
        struct SentinelPartial {
            enabled: Option<bool>,
            model_id: Option<String>,
            stall_threshold: Option<f32>,
            stall_window: Option<u32>,
            regression_threshold: Option<f32>,
            intervention: Option<InterventionLevel>,
            max_embed_input_bytes: Option<usize>,
        }

        #[derive(Deserialize)]
        struct WitnessPartial {
            enabled: Option<bool>,
            max_preimage_bytes: Option<usize>,
            hash_timeout_ms: Option<u64>,
        }

        #[derive(Deserialize)]
        struct LearnerPartial {
            enabled: Option<bool>,
            endpoint: Option<String>,
            flush_interval_ms: Option<u64>,
            max_buffer_events: Option<usize>,
        }

        #[derive(Deserialize)]
        struct ServerPartial {
            url: Option<String>,
            auth_token: Option<String>,
            tls_verify: Option<bool>,
            ca_cert_path: Option<PathBuf>,
            client_cert_path: Option<PathBuf>,
            client_key_path: Option<PathBuf>,
        }

        #[derive(Deserialize)]
        struct FilePartial {
            #[serde(default)]
            sentinel: Option<SentinelPartial>,
            #[serde(default)]
            witness: Option<WitnessPartial>,
            #[serde(default)]
            learner: Option<LearnerPartial>,
            #[serde(default)]
            server: Option<ServerPartial>,
            #[serde(default)]
            standalone: Option<bool>,
            #[serde(default)]
            log_level: Option<String>,
            #[serde(default)]
            tenant_id: Option<Uuid>,
        }

        let partial: FilePartial =
            toml::from_str(raw).map_err(|e| AgentFirewallError::config(e.to_string()))?;

        if let Some(s) = partial.sentinel {
            if let Some(v) = s.enabled {
                self.sentinel.enabled = v;
            }
            if let Some(v) = s.model_id {
                self.sentinel.model_id = v;
            }
            if let Some(v) = s.stall_threshold {
                self.sentinel.stall_threshold = v;
            }
            if let Some(v) = s.stall_window {
                self.sentinel.stall_window = v;
            }
            if let Some(v) = s.regression_threshold {
                self.sentinel.regression_threshold = v;
            }
            if let Some(v) = s.intervention {
                self.sentinel.intervention = v;
            }
            if let Some(v) = s.max_embed_input_bytes {
                self.sentinel.max_embed_input_bytes = v;
            }
        }
        if let Some(s) = partial.witness {
            if let Some(v) = s.enabled {
                self.witness.enabled = v;
            }
            if let Some(v) = s.max_preimage_bytes {
                self.witness.max_preimage_bytes = v;
            }
            if let Some(v) = s.hash_timeout_ms {
                self.witness.hash_timeout_ms = v;
            }
        }
        if let Some(s) = partial.learner {
            if let Some(v) = s.enabled {
                self.learner.enabled = v;
            }
            if let Some(v) = s.endpoint {
                self.learner.endpoint = v;
            }
            if let Some(v) = s.flush_interval_ms {
                self.learner.flush_interval_ms = v;
            }
            if let Some(v) = s.max_buffer_events {
                self.learner.max_buffer_events = v;
            }
        }
        if let Some(s) = partial.server {
            if let Some(v) = s.url {
                self.server.url = v;
            }
            if let Some(v) = s.auth_token {
                self.server.auth_token = v;
            }
            if let Some(v) = s.tls_verify {
                self.server.tls_verify = v;
            }
            if let Some(v) = s.ca_cert_path {
                self.server.ca_cert_path = Some(v);
            }
            if let Some(v) = s.client_cert_path {
                self.server.client_cert_path = Some(v);
            }
            if let Some(v) = s.client_key_path {
                self.server.client_key_path = Some(v);
            }
        }
        if let Some(b) = partial.standalone {
            self.standalone = b;
        }
        if let Some(s) = partial.log_level {
            self.log_level = s;
        }
        if let Some(t) = partial.tenant_id {
            self.tenant_id = Some(t);
        }

        Ok(())
    }

    fn merge_from_env(&mut self) -> Result<(), AgentFirewallError> {
        if let Ok(v) = std::env::var("AGENTVAULT_STANDALONE") {
            self.standalone = parse_bool(&v, "AGENTVAULT_STANDALONE")?;
        }
        if let Ok(v) = std::env::var("AGENTVAULT_LOG_LEVEL") {
            if !v.is_empty() {
                self.log_level = v;
            }
        }
        if let Ok(v) = std::env::var("AGENTVAULT_TENANT_ID") {
            if !v.is_empty() {
                let id = Uuid::parse_str(&v).map_err(|_| AgentFirewallError::InvalidEnvUuid {
                    var: "AGENTVAULT_TENANT_ID",
                    value: v.clone(),
                })?;
                self.tenant_id = Some(id);
            }
        }

        if let Ok(v) = std::env::var("AGENTVAULT_SENTINEL_ENABLED") {
            self.sentinel.enabled = parse_bool(&v, "AGENTVAULT_SENTINEL_ENABLED")?;
        }
        if let Ok(v) = std::env::var("AGENTVAULT_SENTINEL_MODEL") {
            if !v.is_empty() {
                self.sentinel.model_id = v;
            }
        }
        if let Ok(v) = std::env::var("AGENTVAULT_SENTINEL_STALL_THRESHOLD") {
            self.sentinel.stall_threshold = parse_f32(&v, "AGENTVAULT_SENTINEL_STALL_THRESHOLD")?;
        }
        if let Ok(v) = std::env::var("AGENTVAULT_SENTINEL_STALL_WINDOW") {
            self.sentinel.stall_window = parse_u32(&v, "AGENTVAULT_SENTINEL_STALL_WINDOW")?;
        }
        if let Ok(v) = std::env::var("AGENTVAULT_SENTINEL_REGRESSION_THRESHOLD") {
            self.sentinel.regression_threshold =
                parse_f32(&v, "AGENTVAULT_SENTINEL_REGRESSION_THRESHOLD")?;
        }
        if let Ok(v) = std::env::var("AGENTVAULT_SENTINEL_INTERVENTION") {
            self.sentinel.intervention = parse_intervention(&v)?;
        }
        if let Ok(v) = std::env::var("AGENTVAULT_SENTINEL_MAX_EMBED_INPUT_BYTES") {
            self.sentinel.max_embed_input_bytes =
                parse_usize(&v, "AGENTVAULT_SENTINEL_MAX_EMBED_INPUT_BYTES")?;
        }

        if let Ok(v) = std::env::var("AGENTVAULT_WITNESS_ENABLED") {
            self.witness.enabled = parse_bool(&v, "AGENTVAULT_WITNESS_ENABLED")?;
        }
        if let Ok(v) = std::env::var("AGENTVAULT_WITNESS_MAX_PREIMAGE_BYTES") {
            self.witness.max_preimage_bytes =
                parse_usize(&v, "AGENTVAULT_WITNESS_MAX_PREIMAGE_BYTES")?;
        }
        if let Ok(v) = std::env::var("AGENTVAULT_WITNESS_HASH_TIMEOUT_MS") {
            self.witness.hash_timeout_ms = parse_u64(&v, "AGENTVAULT_WITNESS_HASH_TIMEOUT_MS")?;
        }

        if let Ok(v) = std::env::var("AGENTVAULT_LEARNER_ENABLED") {
            self.learner.enabled = parse_bool(&v, "AGENTVAULT_LEARNER_ENABLED")?;
        }
        if let Ok(v) = std::env::var("AGENTVAULT_LEARNER_ENDPOINT") {
            if !v.is_empty() {
                self.learner.endpoint = v;
            }
        }
        if let Ok(v) = std::env::var("AGENTVAULT_LEARNER_FLUSH_INTERVAL_MS") {
            self.learner.flush_interval_ms = parse_u64(&v, "AGENTVAULT_LEARNER_FLUSH_INTERVAL_MS")?;
        }
        if let Ok(v) = std::env::var("AGENTVAULT_LEARNER_MAX_BUFFER_EVENTS") {
            self.learner.max_buffer_events =
                parse_usize(&v, "AGENTVAULT_LEARNER_MAX_BUFFER_EVENTS")?;
        }

        if let Ok(v) = std::env::var("AGENTVAULT_SERVER_URL") {
            if !v.is_empty() {
                self.server.url = v;
            }
        }
        if let Ok(v) = std::env::var("AGENTVAULT_SERVER_AUTH_TOKEN") {
            self.server.auth_token = v;
        }
        if let Ok(v) = std::env::var("AGENTVAULT_SERVER_TLS_VERIFY") {
            self.server.tls_verify = parse_bool(&v, "AGENTVAULT_SERVER_TLS_VERIFY")?;
        }
        if let Ok(v) = std::env::var("AGENTVAULT_SERVER_CA_CERT") {
            if v.is_empty() {
                self.server.ca_cert_path = None;
            } else {
                self.server.ca_cert_path = Some(PathBuf::from(v));
            }
        }
        if let Ok(v) = std::env::var("AGENTVAULT_SERVER_CLIENT_CERT") {
            if v.is_empty() {
                self.server.client_cert_path = None;
            } else {
                self.server.client_cert_path = Some(PathBuf::from(v));
            }
        }
        if let Ok(v) = std::env::var("AGENTVAULT_SERVER_CLIENT_KEY") {
            if v.is_empty() {
                self.server.client_key_path = None;
            } else {
                self.server.client_key_path = Some(PathBuf::from(v));
            }
        }

        Ok(())
    }
}

fn parse_bool(raw: &str, var: &'static str) -> Result<bool, AgentFirewallError> {
    match raw.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(AgentFirewallError::InvalidEnvBool {
            var,
            value: raw.into(),
        }),
    }
}

fn parse_f32(raw: &str, var: &'static str) -> Result<f32, AgentFirewallError> {
    raw.parse().map_err(|_| AgentFirewallError::InvalidEnvNumber {
        var,
        value: raw.into(),
    })
}

fn parse_u32(raw: &str, var: &'static str) -> Result<u32, AgentFirewallError> {
    raw.parse().map_err(|_| AgentFirewallError::InvalidEnvNumber {
        var,
        value: raw.into(),
    })
}

fn parse_u64(raw: &str, var: &'static str) -> Result<u64, AgentFirewallError> {
    raw.parse().map_err(|_| AgentFirewallError::InvalidEnvNumber {
        var,
        value: raw.into(),
    })
}

fn parse_usize(raw: &str, var: &'static str) -> Result<usize, AgentFirewallError> {
    raw.parse().map_err(|_| AgentFirewallError::InvalidEnvNumber {
        var,
        value: raw.into(),
    })
}

fn parse_intervention(raw: &str) -> Result<InterventionLevel, AgentFirewallError> {
    match raw.to_ascii_lowercase().as_str() {
        "warn" => Ok(InterventionLevel::Warn),
        "downgrade" => Ok(InterventionLevel::Downgrade),
        "pause" => Ok(InterventionLevel::Pause),
        "deny" => Ok(InterventionLevel::Deny),
        _ => Err(AgentFirewallError::config(format!(
            "invalid AGENTVAULT_SENTINEL_INTERVENTION: {raw}"
        ))),
    }
}

/// Resolves layered configuration per FR-020.
#[derive(Debug, Clone, Default)]
pub struct ConfigResolver {
    programmatic: AgentFirewallConfig,
}

impl ConfigResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts resolution from defaults only (no programmatic layer).
    pub fn with_programmatic(programmatic: AgentFirewallConfig) -> Self {
        Self { programmatic }
    }

    /// Additional programmatic patches merged into the resolver’s programmatic layer (still below file and env in [`Self::resolve`]).
    pub fn merge_programmatic(mut self, overrides: AgentFirewallConfig) -> Self {
        self.programmatic = self.programmatic.clone().with_overrides(overrides);
        self
    }

    /// Returns **defaults + programmatic + `overrides`** with no file or env layer (for tests and embedded hosts).
    pub fn with_overrides(self, overrides: AgentFirewallConfig) -> AgentFirewallConfig {
        AgentFirewallConfig::default()
            .with_overrides(self.programmatic)
            .with_overrides(overrides)
    }

    /// Loads configuration from `agentfirewall.toml`-shaped contents at `path` (full merge, not layered).
    pub fn from_file(path: &Path) -> Result<AgentFirewallConfig, AgentFirewallError> {
        let text = fs::read_to_string(path).map_err(|e| AgentFirewallError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        let mut cfg = AgentFirewallConfig::default();
        cfg.merge_from_file_partial(&text)?;
        Ok(cfg)
    }

    /// Applies only `AGENTVAULT_*` environment variables on top of defaults.
    pub fn from_env() -> Result<AgentFirewallConfig, AgentFirewallError> {
        let mut cfg = AgentFirewallConfig::default();
        cfg.merge_from_env()?;
        Ok(cfg)
    }

    /// **env > file > programmatic > defaults**. File path: `AGENTFIREWALL_CONFIG` if set, else `./agentfirewall.toml` when present.
    pub fn resolve(self) -> Result<AgentFirewallConfig, AgentFirewallError> {
        let mut cfg = AgentFirewallConfig::default();
        cfg = cfg.with_overrides(self.programmatic);

        let path = std::env::var("AGENTFIREWALL_CONFIG")
            .ok()
            .map(PathBuf::from)
            .filter(|p| p.exists());
        let path = path.or_else(|| {
            let p = PathBuf::from("agentfirewall.toml");
            p.exists().then_some(p)
        });

        if let Some(ref p) = path {
            let text = fs::read_to_string(p).map_err(|e| AgentFirewallError::Io {
                path: p.to_path_buf(),
                source: e,
            })?;
            cfg.merge_from_file_partial(&text)?;
        }

        cfg.merge_from_env()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn env_mutex() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock poisoned")
    }

    #[test]
    fn defaults_are_sane() {
        let c = AgentFirewallConfig::default();
        assert!(!c.standalone);
        assert_eq!(c.log_level, "info");
        assert!(c.server.tls_verify);
    }

    #[test]
    fn from_file_partial_table() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("agentfirewall.toml");
        fs::write(
            &p,
            r#"
[server]
url = "https://example.com"
tls_verify = false

[witness]
enabled = false
"#,
        )
        .unwrap();
        let c = ConfigResolver::from_file(&p).unwrap();
        assert_eq!(c.server.url, "https://example.com");
        assert!(!c.server.tls_verify);
        assert!(!c.witness.enabled);
        assert!(c.sentinel.enabled); // not in file → still default from merge start
    }

    #[test]
    fn with_overrides_patch_sections() {
        let base = AgentFirewallConfig::default();
        let patch = AgentFirewallConfig {
            standalone: true,
            log_level: "debug".into(),
            server: ServerConfigSection {
                url: "https://patch".into(),
                ..ServerConfigSection::default()
            },
            ..AgentFirewallConfig::default()
        };
        let merged = base.with_overrides(patch);
        assert!(merged.standalone);
        assert_eq!(merged.log_level, "debug");
        assert_eq!(merged.server.url, "https://patch");
    }

    #[test]
    fn resolve_layering_env_over_file() {
        let _g = env_mutex();
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("agentfirewall.toml");
        fs::write(
            &p,
            r#"
log_level = "warn"
standalone = false

[server]
url = "https://from-file.example"
"#,
        )
        .unwrap();

        unsafe {
            env::set_var("AGENTFIREWALL_CONFIG", p.to_str().unwrap());
            env::set_var("AGENTVAULT_LOG_LEVEL", "trace");
            env::remove_var("AGENTVAULT_SERVER_URL");
        }

        let cfg = ConfigResolver::new().resolve().expect("resolve");
        assert_eq!(cfg.log_level, "trace");
        assert_eq!(cfg.server.url, "https://from-file.example");

        unsafe {
            env::remove_var("AGENTFIREWALL_CONFIG");
            env::remove_var("AGENTVAULT_LOG_LEVEL");
        }
    }

    #[test]
    fn programmatic_below_file_and_env() {
        let _g = env_mutex();
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("agentfirewall.toml");
        fs::write(
            &p,
            r#"
[server]
url = "https://file wins over prog"
"#,
        )
        .unwrap();

        unsafe {
            env::set_var("AGENTFIREWALL_CONFIG", p.to_str().unwrap());
            env::set_var("AGENTVAULT_SERVER_URL", "https://env-wins.example");
        }

        let prog = AgentFirewallConfig {
            server: ServerConfigSection {
                url: "https://prog.example".into(),
                ..Default::default()
            },
            ..AgentFirewallConfig::default()
        };

        let cfg = ConfigResolver::with_programmatic(prog).resolve().unwrap();
        assert_eq!(cfg.server.url, "https://env-wins.example");

        unsafe {
            env::remove_var("AGENTFIREWALL_CONFIG");
            env::remove_var("AGENTVAULT_SERVER_URL");
        }
    }

    #[test]
    fn invalid_bool_errors() {
        let _g = env_mutex();
        unsafe {
            env::set_var("AGENTVAULT_STANDALONE", "maybe");
        }
        let e = ConfigResolver::from_env().unwrap_err();
        assert!(matches!(e, AgentFirewallError::InvalidEnvBool { .. }));
        unsafe {
            env::remove_var("AGENTVAULT_STANDALONE");
        }
    }
}
