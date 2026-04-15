use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Principal category carried on authenticated requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PrincipalType {
    ApiKey,
    User,
    Service,
}

/// Fine-grained API authorization flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Permission {
    PolicyRead,
    PolicyWrite,
    RunRead,
    RunWrite,
    RunExecute,
    ApprovalRead,
    ApprovalWrite,
    IncidentRead,
    IncidentWrite,
    LearnerRead,
    LearnerWrite,
    WebhookManage,
    AuditRead,
    Admin,
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl FromStr for Permission {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "PolicyRead" | "policy_read" => Ok(Self::PolicyRead),
            "PolicyWrite" | "policy_write" => Ok(Self::PolicyWrite),
            "RunRead" | "run_read" => Ok(Self::RunRead),
            "RunWrite" | "run_write" => Ok(Self::RunWrite),
            "RunExecute" | "run_execute" => Ok(Self::RunExecute),
            "ApprovalRead" | "approval_read" => Ok(Self::ApprovalRead),
            "ApprovalWrite" | "approval_write" => Ok(Self::ApprovalWrite),
            "IncidentRead" | "incident_read" => Ok(Self::IncidentRead),
            "IncidentWrite" | "incident_write" => Ok(Self::IncidentWrite),
            "LearnerRead" | "learner_read" => Ok(Self::LearnerRead),
            "LearnerWrite" | "learner_write" => Ok(Self::LearnerWrite),
            "WebhookManage" | "webhook_manage" => Ok(Self::WebhookManage),
            "AuditRead" | "audit_read" => Ok(Self::AuditRead),
            "Admin" | "admin" => Ok(Self::Admin),
            _ => Err(()),
        }
    }
}

pub fn parse_permissions(raw: &[String]) -> HashSet<Permission> {
    raw.iter()
        .filter_map(|s| Permission::from_str(s).ok())
        .collect()
}

/// Authenticated request context inserted into Axum/Tonic extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthContext {
    pub tenant_id: String,
    pub principal_id: String,
    pub principal_type: PrincipalType,
    pub permissions: HashSet<Permission>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing credentials")]
    MissingCredentials,
    #[error("invalid key")]
    InvalidKey,
    #[error("key revoked")]
    KeyRevoked,
    #[error("key expired")]
    KeyExpired,
    #[error("insufficient permissions: need {required}")]
    InsufficientPermissions {
        required: Permission,
        actual: HashSet<Permission>,
    },
    #[error("internal authentication error: {0}")]
    Internal(String),
}

impl AuthError {
    /// Whether this failure must be surfaced as a generic invalid-credentials response (no key oracle).
    pub fn is_credential_failure(&self) -> bool {
        matches!(
            self,
            AuthError::MissingCredentials
                | AuthError::InvalidKey
                | AuthError::KeyRevoked
                | AuthError::KeyExpired
        )
    }

    /// Stable client-facing message; never distinguishes missing vs revoked vs expired keys.
    pub fn public_message(&self) -> &'static str {
        match self {
            AuthError::InsufficientPermissions { .. } => "permission denied",
            AuthError::Internal(_) => "internal error",
            _ => "invalid credentials",
        }
    }
}
