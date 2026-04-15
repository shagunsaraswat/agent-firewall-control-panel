//! Generated protobuf modules (gRPC client only).
#![allow(dead_code)]

pub mod common {
    #[allow(dead_code)]
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

pub mod incident {
    pub mod v1 {
        tonic::include_proto!("agentfirewall.incident.v1");
    }
}

pub mod approval {
    pub mod v1 {
        tonic::include_proto!("agentfirewall.approval.v1");
    }
}

pub mod learner {
    pub mod v1 {
        tonic::include_proto!("agentfirewall.learner.v1");
    }
}

pub use approval::v1 as approval_v1;
pub use common::v1 as common_v1;
pub use incident::v1 as incident_v1;
pub use learner::v1 as learner_v1;
pub use learner::v1::learner_service_client::LearnerServiceClient;
pub use policy::v1 as policy_v1;
pub use run::v1 as run_v1;
