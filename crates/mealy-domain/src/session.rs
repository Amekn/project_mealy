use serde::{Deserialize, Serialize};

/// Ordering behavior requested for one durably admitted session input.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMode {
    /// Promote the input in FIFO order after the current turn.
    Queue,
    /// Offer the input to the active run at its next safe model or tool boundary.
    SteerAtBoundary,
    /// Request cancellation of active work and then promote the input in FIFO order.
    InterruptThenQueue,
}

impl DeliveryMode {
    /// Returns the stable storage and protocol spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queue => "queue",
            Self::SteerAtBoundary => "steer_at_boundary",
            Self::InterruptThenQueue => "interrupt_then_queue",
        }
    }
}
