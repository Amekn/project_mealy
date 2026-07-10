use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use uuid::Uuid;

macro_rules! define_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a time-ordered `UUIDv7` identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Wraps an existing UUID.
            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            /// Returns the underlying UUID value.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value).map(Self)
            }
        }
    };
}

define_id!(
    /// Identifies an authenticated user, service, or runtime identity.
    PrincipalId
);
define_id!(
    /// Identifies a verified mapping between a channel identity and a principal.
    ChannelBindingId
);
define_id!(
    /// Identifies an ordered conversation and durable input inbox.
    SessionId
);
define_id!(
    /// Identifies one accepted session input.
    InboxEntryId
);
define_id!(
    /// Identifies one promoted session input and its response work.
    TurnId
);
define_id!(
    /// Identifies a user-visible unit of work.
    TaskId
);
define_id!(
    /// Identifies one agent execution lineage.
    RunId
);
define_id!(
    /// Identifies one bounded model, tool, or validation attempt within a run.
    AttemptId
);
define_id!(
    /// Identifies one normalized invocation of a declared tool.
    ToolCallId
);
define_id!(
    /// Identifies an operation that may change state outside Mealy.
    EffectId
);
define_id!(
    /// Identifies a bound authorization decision for an effect.
    ApprovalId
);
define_id!(
    /// Identifies immutable content in the artifact store.
    ArtifactId
);
define_id!(
    /// Identifies the exact material assembled for one model request.
    ContextManifestId
);
define_id!(
    /// Identifies a governed long-term memory.
    MemoryId
);
define_id!(
    /// Identifies an independent validation record.
    ValidationId
);
define_id!(
    /// Identifies a durable worker lease.
    LeaseId
);
define_id!(
    /// Identifies an immutable journal event.
    EventId
);
define_id!(
    /// Identifies one durable outbound delivery.
    OutboxId
);
define_id!(
    /// Identifies related commands, events, attempts, and effects.
    CorrelationId
);

#[cfg(test)]
mod tests {
    use super::TaskId;

    #[test]
    fn identifiers_round_trip_as_strings() {
        let id = TaskId::new();
        let parsed = id.to_string().parse::<TaskId>().expect("valid task id");
        assert_eq!(parsed, id);
        assert_eq!(id.as_uuid().get_version_num(), 7);
    }
}
