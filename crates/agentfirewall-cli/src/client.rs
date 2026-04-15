//! Shared gRPC channel and metadata injection for control-plane clients.
#![allow(clippy::result_large_err)]

use std::error::Error;
use std::fmt;

use anyhow::Result;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::{Request, Status};

/// Machine-readable CLI error aligned with the REST error envelope `code` field (see `docs/api/error-envelope.md`).
#[derive(Debug, Clone)]
pub struct AvCliError {
    pub code: &'static str,
    pub message: String,
}

impl fmt::Display for AvCliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for AvCliError {}

pub async fn connect_channel(url: &str) -> Result<Channel> {
    let endpoint = Channel::from_shared(url.to_owned()).map_err(|e| AvCliError {
        code: "INVALID_ARGUMENT",
        message: format!("invalid gRPC URL (AV_SERVER_URL): {e}"),
    })?;
    Ok(endpoint
        .connect()
        .await
        .map_err(|e| AvCliError {
            code: "UNAVAILABLE",
            message: format!(
                "Failed to open a gRPC connection to {url}.\n\
                 Check that the control plane is running and AV_SERVER_URL is correct.\n\
                 For a local dev server try: export AV_SERVER_URL=http://127.0.0.1:50051\n\
                 Details: {e}"
            ),
        })?)
}

/// Attaches `x-api-key` (when non-empty) and `x-tenant-id` to every outbound call.
pub fn metadata_interceptor(
    api_key: Option<String>,
    tenant_id: String,
) -> impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone + Send + 'static {
    move |mut req: Request<()>| {
        if let Some(ref k) = api_key {
            if !k.is_empty() {
                if let Ok(v) = MetadataValue::try_from(k.as_str()) {
                    req.metadata_mut().insert("x-api-key", v);
                }
            }
        }
        match MetadataValue::try_from(tenant_id.as_str()) {
            Ok(v) => {
                req.metadata_mut().insert("x-tenant-id", v);
            }
            Err(_) => {
                return Err(Status::invalid_argument(
                    "AV_TENANT_ID must be visible-ASCII for gRPC metadata",
                ));
            }
        }
        Ok(req)
    }
}
