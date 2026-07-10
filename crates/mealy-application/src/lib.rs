//! Application use cases and infrastructure ports.

mod ports;
mod recovery;
mod sessions;

pub use ports::{Clock, IdGenerator};
pub use recovery::{RecoveryPlan, plan_interrupted_effect};
pub use sessions::{
    AdmitInputCommand, InputAdmissionCommit, InputAdmissionLimits, InputAdmissionOutcome,
    InputAdmissionReceipt, OwnershipContext, SessionCreationCommit, SessionStore,
    SessionStoreError, SessionUseCaseError, admit_input, create_session,
};
