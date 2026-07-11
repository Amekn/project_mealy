use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Whether an operation observes state or can mutate an external system.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    /// The operation cannot change external state.
    ReadOnly,
    /// The operation mutates state and has a declared compensating operation.
    Reversible,
    /// Repeating the same normalized operation is safe by contract or stable key.
    Idempotent,
    /// Repeating the same normalized operation can duplicate or corrupt state.
    NonIdempotent,
}

impl EffectClass {
    /// Returns whether this class can change external state.
    #[must_use]
    pub const fn is_mutating(self) -> bool {
        !matches!(self, Self::ReadOnly)
    }
}

/// Policy-visible risk assigned to a task or tool.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    /// Bounded, readily inspectable impact.
    Low,
    /// Material impact requiring stronger evidence or validation.
    Medium,
    /// High-impact operation requiring the strongest policy controls.
    High,
}

/// Declared response to an interrupted or ambiguous effect dispatch.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStrategy {
    /// Repeat only when the idempotency declaration proves repetition safe.
    Retry,
    /// Determine the external outcome before another dispatch.
    Reconcile,
    /// Execute a declared compensating operation.
    Compensate,
    /// Never dispatch the operation automatically after interruption.
    NeverRetry,
}

/// Runtime boundary responsible for executing a tool.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub enum ExecutorKind {
    /// First-party operation that does not need an external sandbox process.
    Builtin,
    /// First-party sandbox worker process.
    Sandbox,
    /// Out-of-process extension identified by a stable extension ID.
    Extension(String),
    /// Provider-hosted tool execution.
    Provider,
}

impl ExecutorKind {
    /// Creates a validated extension executor identity.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorKindError`] when the ID is empty, oversized, or non-canonical.
    pub fn extension(extension_id: impl Into<String>) -> Result<Self, ExecutorKindError> {
        let extension_id = extension_id.into();
        validate_extension_id(&extension_id)?;
        Ok(Self::Extension(extension_id))
    }

    /// Returns the extension ID for an extension executor.
    #[must_use]
    pub fn extension_id(&self) -> Option<&str> {
        match self {
            Self::Extension(extension_id) => Some(extension_id),
            Self::Builtin | Self::Sandbox | Self::Provider => None,
        }
    }

    /// Returns the architecture contract spelling.
    #[must_use]
    pub fn as_contract(&self) -> String {
        match self {
            Self::Builtin => "builtin".to_owned(),
            Self::Sandbox => "sandbox".to_owned(),
            Self::Extension(extension_id) => format!("extension:{extension_id}"),
            Self::Provider => "provider".to_owned(),
        }
    }
}

impl TryFrom<String> for ExecutorKind {
    type Error = ExecutorKindError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "builtin" => Ok(Self::Builtin),
            "sandbox" => Ok(Self::Sandbox),
            "provider" => Ok(Self::Provider),
            _ => value
                .strip_prefix("extension:")
                .ok_or(ExecutorKindError::InvalidContract)
                .and_then(Self::extension),
        }
    }
}

impl From<ExecutorKind> for String {
    fn from(value: ExecutorKind) -> Self {
        value.as_contract()
    }
}

fn validate_extension_id(extension_id: &str) -> Result<(), ExecutorKindError> {
    let canonical = !extension_id.is_empty()
        && extension_id.len() <= 128
        && extension_id != "."
        && extension_id != ".."
        && extension_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if canonical {
        Ok(())
    } else {
        Err(ExecutorKindError::InvalidExtensionId)
    }
}

/// Invalid serialized or constructed executor identity.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ExecutorKindError {
    /// The executor contract is not a supported architecture spelling.
    #[error("executor kind is not a supported contract value")]
    InvalidContract,
    /// The extension ID is not a bounded canonical identifier.
    #[error("extension executor ID is not canonical")]
    InvalidExtensionId,
}

#[cfg(test)]
mod tests {
    use super::{ExecutorKind, ExecutorKindError};

    #[test]
    fn extension_executor_uses_the_architecture_contract_spelling() {
        let executor = ExecutorKind::extension("example.extension").expect("valid extension ID");
        let encoded = serde_json::to_string(&executor).expect("serialize executor");
        assert_eq!(encoded, "\"extension:example.extension\"");
        assert_eq!(
            serde_json::from_str::<ExecutorKind>(&encoded).expect("deserialize executor"),
            executor
        );
    }

    #[test]
    fn extension_executor_rejects_ambiguous_or_ambient_identifiers() {
        for invalid in ["", ".", "..", "has/slash", "has:colon", "has space"] {
            assert_eq!(
                ExecutorKind::extension(invalid),
                Err(ExecutorKindError::InvalidExtensionId)
            );
        }
        assert!(serde_json::from_str::<ExecutorKind>("\"extension:\"").is_err());
        assert!(serde_json::from_str::<ExecutorKind>("\"unknown\"").is_err());
    }
}
