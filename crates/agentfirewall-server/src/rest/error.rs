use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use crate::app::error::AppError;
use crate::auth::AuthError;

#[derive(Serialize)]
pub struct ErrorEnvelope {
    pub error: ErrorBody,
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl ErrorEnvelope {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: ErrorBody {
                code: code.into(),
                message: message.into(),
                reason_code: None,
                request_id: None,
            },
        }
    }
}

pub fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(ErrorEnvelope::new(code, message))).into_response()
}

pub fn bad_request(message: &str) -> Response {
    error_response(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT", message)
}

pub fn auth_error_response(err: AuthError) -> Response {
    match err {
        AuthError::InsufficientPermissions { .. } => error_response(
            StatusCode::FORBIDDEN,
            "PERMISSION_DENIED",
            "Permission denied.",
        ),
        AuthError::Internal(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Internal error.",
        ),
        _ => error_response(
            StatusCode::UNAUTHORIZED,
            "AUTH_INVALID_CREDENTIALS",
            "Invalid credentials.",
        ),
    }
}

impl From<AppError> for Response {
    fn from(e: AppError) -> Self {
        let (status, code) = match &e {
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            AppError::InvalidArgument(_) => (StatusCode::BAD_REQUEST, "INVALID_ARGUMENT"),
            AppError::AlreadyExists(_) => (StatusCode::CONFLICT, "ALREADY_EXISTS"),
            AppError::FailedPrecondition(_) => {
                (StatusCode::PRECONDITION_FAILED, "FAILED_PRECONDITION")
            }
            AppError::PermissionDenied(_) => (StatusCode::FORBIDDEN, "PERMISSION_DENIED"),
            AppError::Unauthenticated(_) => (StatusCode::UNAUTHORIZED, "UNAUTHENTICATED"),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
            AppError::Unavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, "UNAVAILABLE"),
            AppError::Unimplemented(_) => (StatusCode::NOT_IMPLEMENTED, "NOT_IMPLEMENTED"),
        };
        error_response(status, code, &e.to_string())
    }
}
