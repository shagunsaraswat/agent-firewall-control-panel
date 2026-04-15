//! Authentication, tenant scoping, and API key validation.

mod api_key;
mod middleware;
mod tenant;
pub mod types;

pub use api_key::ApiKeyAuth;
pub use middleware::{
    extract_grpc_api_key, extract_http_api_key, require_permission, AuthInterceptor, AuthLayer,
    AuthService,
};
pub use tenant::{TenantId, TenantMiddleware, TenantScope, TenantService};
pub use types::{AuthContext, AuthError, Permission, PrincipalType};

use tonic::{Request, Status};
use uuid::Uuid;

/// Extracts `AuthContext` from gRPC request extensions (inserted by `AuthInterceptor`).
/// Must be called BEFORE `request.into_inner()`.
pub fn extract_auth<T>(request: &Request<T>) -> Result<AuthContext, Status> {
    request
        .extensions()
        .get::<AuthContext>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("missing authentication context"))
}

/// Extracts authenticated tenant UUID from `AuthContext`.
pub fn authenticated_tenant<T>(request: &Request<T>) -> Result<(AuthContext, Uuid), Status> {
    let ctx = extract_auth(request)?;
    let tenant_id = Uuid::parse_str(&ctx.tenant_id)
        .map_err(|e| Status::internal(format!("invalid tenant_id in auth context: {e}")))?;
    Ok((ctx, tenant_id))
}

/// Verifies that a client-supplied scope_id matches the authenticated tenant.
/// Returns the authenticated tenant UUID on success.
pub fn verify_scope_tenant(ctx: &AuthContext, scope_id: &str) -> Result<Uuid, Status> {
    let scope_uuid = Uuid::parse_str(scope_id.trim())
        .map_err(|e| Status::invalid_argument(format!("scope.scope_id: {e}")))?;
    let auth_tenant = Uuid::parse_str(&ctx.tenant_id)
        .map_err(|e| Status::internal(format!("auth tenant: {e}")))?;
    if scope_uuid != auth_tenant {
        return Err(Status::permission_denied(
            "scope does not match authenticated tenant",
        ));
    }
    Ok(auth_tenant)
}
