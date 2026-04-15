//! Auth helper coverage: tenant extraction, scope checks, permissions, and `Permission` parsing.

use std::collections::HashSet;
use std::str::FromStr;

use crate::auth::{
    authenticated_tenant, require_permission, verify_scope_tenant, AuthContext, Permission,
    PrincipalType,
};
use tonic::Request;
use uuid::Uuid;

fn ctx_with_perms(tenant: Uuid, perms: impl IntoIterator<Item = Permission>) -> AuthContext {
    AuthContext {
        tenant_id: tenant.to_string(),
        principal_id: "test".into(),
        principal_type: PrincipalType::ApiKey,
        permissions: HashSet::from_iter(perms),
    }
}

#[test]
fn unauthenticated_request_is_rejected() {
    let req = Request::new(());
    let result = authenticated_tenant(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
}

#[test]
fn authenticated_tenant_ok_when_context_in_extensions() {
    let tenant = Uuid::new_v4();
    let ctx = ctx_with_perms(tenant, [Permission::PolicyRead]);
    let mut req = Request::new(());
    req.extensions_mut().insert(ctx.clone());
    let (got_ctx, got_tid) = authenticated_tenant(&req).expect("authenticated");
    assert_eq!(got_tid, tenant);
    assert_eq!(got_ctx.tenant_id, ctx.tenant_id);
}

#[test]
fn authenticated_tenant_fails_on_invalid_tenant_uuid_in_context() {
    let ctx = AuthContext {
        tenant_id: "not-a-uuid".into(),
        principal_id: "test".into(),
        principal_type: PrincipalType::ApiKey,
        permissions: HashSet::from([Permission::PolicyRead]),
    };
    let mut req = Request::new(());
    req.extensions_mut().insert(ctx);
    let err = authenticated_tenant(&req).expect_err("invalid tenant");
    assert_eq!(err.code(), tonic::Code::Internal);
}

#[test]
fn scope_mismatch_is_denied() {
    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    let ctx = ctx_with_perms(tenant_a, [Permission::PolicyRead]);
    let err = verify_scope_tenant(&ctx, &tenant_b.to_string()).expect_err("scope mismatch");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[test]
fn scope_match_returns_tenant_uuid() {
    let tenant = Uuid::new_v4();
    let ctx = ctx_with_perms(tenant, [Permission::ApprovalRead]);
    let got = verify_scope_tenant(&ctx, &tenant.to_string()).expect("scope ok");
    assert_eq!(got, tenant);
}

#[test]
fn verify_scope_rejects_invalid_scope_uuid() {
    let tenant = Uuid::new_v4();
    let ctx = ctx_with_perms(tenant, []);
    let err = verify_scope_tenant(&ctx, "not-a-uuid").expect_err("bad scope");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[test]
fn missing_permission_policy_write_is_denied() {
    let ctx = ctx_with_perms(Uuid::new_v4(), [Permission::PolicyRead]);
    let err = require_permission(&ctx, Permission::PolicyWrite).expect_err("denied");
    match err {
        crate::auth::AuthError::InsufficientPermissions { required, .. } => {
            assert_eq!(required, Permission::PolicyWrite);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn correct_permission_is_allowed() {
    let ctx = ctx_with_perms(Uuid::new_v4(), [Permission::PolicyWrite]);
    require_permission(&ctx, Permission::PolicyWrite).expect("allowed");
}

#[test]
fn admin_bypasses_specific_permission_requirement() {
    let ctx = ctx_with_perms(Uuid::new_v4(), [Permission::Admin]);
    require_permission(&ctx, Permission::PolicyWrite).expect("admin may write policy");
    require_permission(&ctx, Permission::RunExecute).expect("admin may execute runs");
}

#[test]
fn major_permissions_denied_when_not_granted() {
    let cases = [
        (
            HashSet::from([Permission::PolicyRead]),
            Permission::PolicyWrite,
        ),
        (HashSet::from([Permission::RunRead]), Permission::RunWrite),
        (HashSet::from([Permission::RunRead]), Permission::RunExecute),
        (
            HashSet::from([Permission::ApprovalRead]),
            Permission::ApprovalWrite,
        ),
        (
            HashSet::from([Permission::IncidentRead]),
            Permission::IncidentWrite,
        ),
        (
            HashSet::from([Permission::LearnerRead]),
            Permission::LearnerWrite,
        ),
        (HashSet::new(), Permission::WebhookManage),
        (HashSet::new(), Permission::AuditRead),
    ];
    for (have, need) in cases {
        let ctx = AuthContext {
            tenant_id: Uuid::new_v4().to_string(),
            principal_id: "test".into(),
            principal_type: PrincipalType::ApiKey,
            permissions: have,
        };
        assert!(
            require_permission(&ctx, need).is_err(),
            "expected denial when requiring {need:?}"
        );
    }
}

#[test]
fn permission_from_str_maps_all_variants() {
    let cases: &[(&str, Permission)] = &[
        ("PolicyRead", Permission::PolicyRead),
        ("policy_read", Permission::PolicyRead),
        ("PolicyWrite", Permission::PolicyWrite),
        ("policy_write", Permission::PolicyWrite),
        ("RunRead", Permission::RunRead),
        ("run_read", Permission::RunRead),
        ("RunWrite", Permission::RunWrite),
        ("RunExecute", Permission::RunExecute),
        ("run_execute", Permission::RunExecute),
        ("ApprovalRead", Permission::ApprovalRead),
        ("approval_read", Permission::ApprovalRead),
        ("ApprovalWrite", Permission::ApprovalWrite),
        ("IncidentRead", Permission::IncidentRead),
        ("IncidentWrite", Permission::IncidentWrite),
        ("LearnerRead", Permission::LearnerRead),
        ("LearnerWrite", Permission::LearnerWrite),
        ("WebhookManage", Permission::WebhookManage),
        ("webhook_manage", Permission::WebhookManage),
        ("AuditRead", Permission::AuditRead),
        ("Admin", Permission::Admin),
        ("admin", Permission::Admin),
    ];
    for (s, expected) in cases {
        let parsed = Permission::from_str(s).unwrap_or_else(|_| panic!("parse {s:?}"));
        assert_eq!(parsed, *expected, "input {s:?}");
    }
    assert!(Permission::from_str("").is_err());
    assert!(Permission::from_str("UnknownPerm").is_err());
}
