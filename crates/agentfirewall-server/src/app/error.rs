use std::fmt;

#[derive(Debug)]
pub enum AppError {
    NotFound(String),
    InvalidArgument(String),
    AlreadyExists(String),
    FailedPrecondition(String),
    PermissionDenied(String),
    Unauthenticated(String),
    Internal(String),
    Unavailable(String),
    Unimplemented(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(m) => write!(f, "not found: {m}"),
            Self::InvalidArgument(m) => write!(f, "invalid argument: {m}"),
            Self::AlreadyExists(m) => write!(f, "already exists: {m}"),
            Self::FailedPrecondition(m) => write!(f, "failed precondition: {m}"),
            Self::PermissionDenied(m) => write!(f, "permission denied: {m}"),
            Self::Unauthenticated(m) => write!(f, "unauthenticated: {m}"),
            Self::Internal(m) => write!(f, "internal error: {m}"),
            Self::Unavailable(m) => write!(f, "unavailable: {m}"),
            Self::Unimplemented(m) => write!(f, "unimplemented: {m}"),
        }
    }
}

impl std::error::Error for AppError {}

impl From<AppError> for tonic::Status {
    fn from(e: AppError) -> Self {
        match e {
            AppError::NotFound(m) => tonic::Status::not_found(m),
            AppError::InvalidArgument(m) => tonic::Status::invalid_argument(m),
            AppError::AlreadyExists(m) => tonic::Status::already_exists(m),
            AppError::FailedPrecondition(m) => tonic::Status::failed_precondition(m),
            AppError::PermissionDenied(m) => tonic::Status::permission_denied(m),
            AppError::Unauthenticated(m) => tonic::Status::unauthenticated(m),
            AppError::Internal(m) => tonic::Status::internal(m),
            AppError::Unavailable(m) => tonic::Status::unavailable(m),
            AppError::Unimplemented(m) => tonic::Status::unimplemented(m),
        }
    }
}
