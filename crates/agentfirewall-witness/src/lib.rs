//! State-witness revalidation for Agent FirewallKit.
//!
//! Capture canonical state at approval time, hash it, and revalidate before execution.

pub mod canonical;
pub mod capture;
pub mod guard;
pub mod hash;
pub mod revalidation;

pub use canonical::{canonicalize, CanonicalError};
pub use capture::{
    StateSnapshot, WitnessCapture, WitnessError, CURRENT_FORMAT_VERSION, MAX_SNAPSHOT_SIZE,
};
pub use guard::WitnessGuard;
pub use hash::{compute_witness_hash, constant_time_compare};
pub use revalidation::{RevalidationOutcome, Revalidator};
