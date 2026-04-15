use sqlx::PgPool;

use crate::services::approval::ApprovalServiceImpl;
use crate::services::incident::IncidentServiceImpl;
use crate::services::learner::LearnerServiceImpl;
use crate::services::policy::PolicyServiceImpl;
use crate::services::run::RunServiceImpl;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub policy_svc: PolicyServiceImpl,
    pub run_svc: RunServiceImpl,
    pub approval_svc: ApprovalServiceImpl,
    pub incident_svc: IncidentServiceImpl,
    pub learner_svc: LearnerServiceImpl,
}
