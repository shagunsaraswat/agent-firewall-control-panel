use std::env;
use std::net::SocketAddr;
use std::str::FromStr;

use thiserror::Error;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub grpc_addr: SocketAddr,
    pub metrics_addr: SocketAddr,
    pub database_url: String,
    pub redis_url: String,
    pub nats_url: String,
    pub clickhouse_url: String,
    pub max_db_connections: u32,
    pub request_timeout_secs: u64,
    pub cors_origins: Vec<String>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub idempotency_ttl_secs: u64,
    pub http_api_enabled: bool,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required environment variable: {0}")]
    MissingEnv(&'static str),
    #[error("invalid environment variable {key}: {message}")]
    InvalidEnv { key: &'static str, message: String },
    #[error(
        "TLS: both AV_TLS_CERT_PATH and AV_TLS_KEY_PATH must be set together, or both omitted"
    )]
    TlsMismatch,
}

impl ServerConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let database_url =
            env::var("AV_DATABASE_URL").map_err(|_| ConfigError::MissingEnv("AV_DATABASE_URL"))?;

        let listen_addr = parse_socket_addr(
            "AV_LISTEN_ADDR",
            env::var("AV_LISTEN_ADDR").ok().as_deref(),
            "0.0.0.0:8080",
        )?;

        let grpc_addr = parse_socket_addr(
            "AV_GRPC_ADDR",
            env::var("AV_GRPC_ADDR").ok().as_deref(),
            "0.0.0.0:50051",
        )?;

        let metrics_addr = parse_socket_addr(
            "AV_METRICS_ADDR",
            env::var("AV_METRICS_ADDR").ok().as_deref(),
            "0.0.0.0:9090",
        )?;

        let redis_url =
            env::var("AV_REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

        let nats_url =
            env::var("AV_NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".to_string());

        let clickhouse_url =
            env::var("AV_CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_string());

        let max_db_connections = parse_u32(
            "AV_MAX_DB_CONNECTIONS",
            env::var("AV_MAX_DB_CONNECTIONS").ok().as_deref(),
            20,
        )?;

        let request_timeout_secs = parse_u64(
            "AV_REQUEST_TIMEOUT_SECS",
            env::var("AV_REQUEST_TIMEOUT_SECS").ok().as_deref(),
            30,
        )?;

        let cors_origins = parse_cors_origins(env::var("AV_CORS_ORIGINS").ok().as_deref())?;

        let tls_cert_path = env::var("AV_TLS_CERT_PATH").ok().filter(|s| !s.is_empty());
        let tls_key_path = env::var("AV_TLS_KEY_PATH").ok().filter(|s| !s.is_empty());

        match (&tls_cert_path, &tls_key_path) {
            (Some(_), Some(_)) | (None, None) => {}
            _ => return Err(ConfigError::TlsMismatch),
        }

        let idempotency_ttl_secs = parse_u64(
            "AV_IDEMPOTENCY_TTL_SECS",
            env::var("AV_IDEMPOTENCY_TTL_SECS").ok().as_deref(),
            300,
        )?;

        let http_api_enabled = env::var("AV_HTTP_API_ENABLED")
            .ok()
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(true);

        Ok(Self {
            listen_addr,
            grpc_addr,
            metrics_addr,
            database_url,
            redis_url,
            nats_url,
            clickhouse_url,
            max_db_connections,
            request_timeout_secs,
            cors_origins,
            tls_cert_path,
            tls_key_path,
            idempotency_ttl_secs,
            http_api_enabled,
        })
    }
}

fn parse_socket_addr(
    key: &'static str,
    raw: Option<&str>,
    default: &str,
) -> Result<SocketAddr, ConfigError> {
    let s = raw.unwrap_or(default);
    SocketAddr::from_str(s).map_err(|e| ConfigError::InvalidEnv {
        key,
        message: e.to_string(),
    })
}

fn parse_u32(key: &'static str, raw: Option<&str>, default: u32) -> Result<u32, ConfigError> {
    match raw {
        None | Some("") => Ok(default),
        Some(s) => s.parse().map_err(|e| ConfigError::InvalidEnv {
            key,
            message: format!("{e}"),
        }),
    }
}

fn parse_u64(key: &'static str, raw: Option<&str>, default: u64) -> Result<u64, ConfigError> {
    match raw {
        None | Some("") => Ok(default),
        Some(s) => s.parse().map_err(|e| ConfigError::InvalidEnv {
            key,
            message: format!("{e}"),
        }),
    }
}

fn parse_cors_origins(raw: Option<&str>) -> Result<Vec<String>, ConfigError> {
    match raw {
        None | Some("") => Ok(vec!["*".to_string()]),
        Some(s) => Ok(s
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_av_keys() {
        for k in [
            "AV_DATABASE_URL",
            "AV_LISTEN_ADDR",
            "AV_GRPC_ADDR",
            "AV_METRICS_ADDR",
            "AV_REDIS_URL",
            "AV_NATS_URL",
            "AV_CLICKHOUSE_URL",
            "AV_MAX_DB_CONNECTIONS",
            "AV_REQUEST_TIMEOUT_SECS",
            "AV_CORS_ORIGINS",
            "AV_TLS_CERT_PATH",
            "AV_TLS_KEY_PATH",
            "AV_IDEMPOTENCY_TTL_SECS",
            "AV_HTTP_API_ENABLED",
        ] {
            env::remove_var(k);
        }
    }

    #[test]
    fn from_env_requires_database_url() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_av_keys();
        let err = ServerConfig::from_env().unwrap_err();
        assert!(matches!(err, ConfigError::MissingEnv("AV_DATABASE_URL")));
    }

    #[test]
    fn from_env_defaults_and_cors_star() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_av_keys();
        env::set_var("AV_DATABASE_URL", "postgres://localhost/db");
        let c = ServerConfig::from_env().unwrap();
        assert_eq!(c.listen_addr.to_string(), "0.0.0.0:8080");
        assert_eq!(c.grpc_addr.to_string(), "0.0.0.0:50051");
        assert_eq!(c.metrics_addr.to_string(), "0.0.0.0:9090");
        assert_eq!(c.redis_url, "redis://localhost:6379");
        assert_eq!(c.nats_url, "nats://localhost:4222");
        assert_eq!(c.clickhouse_url, "http://localhost:8123");
        assert_eq!(c.max_db_connections, 20);
        assert_eq!(c.request_timeout_secs, 30);
        assert_eq!(c.cors_origins, vec!["*".to_string()]);
        assert!(c.tls_cert_path.is_none() && c.tls_key_path.is_none());
        clear_av_keys();
    }

    #[test]
    fn tls_both_or_neither() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_av_keys();
        env::set_var("AV_DATABASE_URL", "postgres://localhost/db");
        env::set_var("AV_TLS_CERT_PATH", "/tmp/cert.pem");
        let err = ServerConfig::from_env().unwrap_err();
        assert!(matches!(err, ConfigError::TlsMismatch));
        clear_av_keys();
    }

    #[test]
    fn cors_parses_csv() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_av_keys();
        env::set_var("AV_DATABASE_URL", "postgres://localhost/db");
        env::set_var("AV_CORS_ORIGINS", "https://a.com, https://b.com ");
        let c = ServerConfig::from_env().unwrap();
        assert_eq!(
            c.cors_origins,
            vec!["https://a.com".to_string(), "https://b.com".to_string()]
        );
        clear_av_keys();
    }
}
