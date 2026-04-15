//! Generated protobuf modules and re-exports for gRPC clients and servers.

pub mod common {
    pub mod v1 {
        tonic::include_proto!("agentfirewall.common.v1");
    }
}

pub mod policy {
    pub mod v1 {
        tonic::include_proto!("agentfirewall.policy.v1");
    }
}

pub mod run {
    pub mod v1 {
        tonic::include_proto!("agentfirewall.run.v1");
    }
}

pub mod approval {
    pub mod v1 {
        tonic::include_proto!("agentfirewall.approval.v1");
    }
}

pub mod incident {
    pub mod v1 {
        tonic::include_proto!("agentfirewall.incident.v1");
    }
}

pub mod learner {
    pub mod v1 {
        tonic::include_proto!("agentfirewall.learner.v1");
    }
}

pub use self::approval::v1::approval_service_client::ApprovalServiceClient;
pub use self::approval::v1::approval_service_server::{ApprovalService, ApprovalServiceServer};
pub use self::incident::v1::incident_service_client::IncidentServiceClient;
pub use self::incident::v1::incident_service_server::{IncidentService, IncidentServiceServer};
pub use self::learner::v1::learner_service_client::LearnerServiceClient;
pub use self::learner::v1::learner_service_server::{LearnerService, LearnerServiceServer};
pub use self::policy::v1::policy_service_client::PolicyServiceClient;
pub use self::policy::v1::policy_service_server::{PolicyService, PolicyServiceServer};
pub use self::run::v1::run_service_client::RunServiceClient;
pub use self::run::v1::run_service_server::{RunService, RunServiceServer};

pub use approval::v1 as approval_v1;
pub use common::v1 as common_v1;
pub use incident::v1 as incident_v1;
pub use learner::v1 as learner_v1;
pub use policy::v1 as policy_v1;
pub use run::v1 as run_v1;
