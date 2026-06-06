use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            pub fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

id_type!(AgentId);
id_type!(AgentRunId);
id_type!(ApprovalId);
id_type!(ArtifactId);
id_type!(ChannelId);
id_type!(ContextBundleId);
id_type!(EventId);
id_type!(MemoryId);
id_type!(PluginId);
id_type!(PrincipalId);
id_type!(ProviderId);
id_type!(SessionId);
id_type!(TaskId);
id_type!(ToolCallId);
id_type!(ValidationRunId);
id_type!(WorkflowId);
