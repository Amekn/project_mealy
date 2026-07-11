use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

/// Versioned data-only skill manifest contract.
pub const SKILL_MANIFEST_CONTRACT_VERSION: &str = "mealy.skill.v1";

/// A digest-pinned instruction or passive resource carried by a skill package.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillAsset {
    /// Safe package-relative path.
    pub relative_path: String,
    /// Declared media type.
    pub media_type: String,
    /// SHA-256 digest of the exact asset bytes.
    pub content_digest: String,
    /// Exact bounded asset size.
    pub size_bytes: u64,
}

/// One separately governed tool contract a skill may ask an agent to use.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillToolRequirement {
    /// Stable tool identifier resolved by the normal capability broker.
    pub tool_id: String,
    /// Exact required tool-contract version.
    pub version: String,
    /// SHA-256 digest of the reviewed input schema.
    pub input_schema_digest: String,
}

/// Versioned instructions and passive resources with no executable authority of their own.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillManifest {
    /// Exact contract version.
    pub contract_version: String,
    /// Stable package identity.
    pub skill_id: String,
    /// Immutable package revision.
    pub version: String,
    /// Ordered instruction assets loaded into governed context.
    pub instructions: Vec<SkillAsset>,
    /// Passive supporting resources loaded only through context/resource policy.
    pub resources: Vec<SkillAsset>,
    /// Executable behavior referenced as separately reviewed tools.
    pub required_tools: BTreeSet<SkillToolRequirement>,
}

impl SkillManifest {
    /// Validates bounded data-only package identity, assets, and tool references.
    ///
    /// # Errors
    ///
    /// Returns [`SkillManifestError`] for malformed, unsafe, duplicate, or unbounded evidence.
    pub fn validate(&self) -> Result<(), SkillManifestError> {
        if self.contract_version != SKILL_MANIFEST_CONTRACT_VERSION {
            return Err(SkillManifestError::UnsupportedContract);
        }
        if !valid_identifier(&self.skill_id, 128) || !valid_identifier(&self.version, 128) {
            return Err(SkillManifestError::InvalidIdentity);
        }
        if self.instructions.is_empty()
            || self.instructions.len() > 64
            || self.resources.len() > 256
            || self.required_tools.len() > 128
        {
            return Err(SkillManifestError::InvalidBounds);
        }
        let mut paths = BTreeSet::new();
        let mut total_bytes = 0_u64;
        for asset in self.instructions.iter().chain(&self.resources) {
            validate_asset(asset)?;
            if !paths.insert(asset.relative_path.as_str()) {
                return Err(SkillManifestError::DuplicateAsset);
            }
            total_bytes = total_bytes
                .checked_add(asset.size_bytes)
                .ok_or(SkillManifestError::InvalidBounds)?;
        }
        if total_bytes > 64 * 1024 * 1024
            || self.instructions.iter().any(|asset| {
                !matches!(
                    asset.media_type.as_str(),
                    "text/plain" | "text/markdown" | "application/json"
                )
            })
        {
            return Err(SkillManifestError::InvalidBounds);
        }
        if self.required_tools.iter().any(|tool| {
            !valid_identifier(&tool.tool_id, 128)
                || !valid_identifier(&tool.version, 128)
                || !valid_sha256(&tool.input_schema_digest)
        }) {
            return Err(SkillManifestError::InvalidToolReference);
        }
        Ok(())
    }
}

/// Invalid skill package evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SkillManifestError {
    /// Contract version is not supported.
    #[error("skill manifest contract version is unsupported")]
    UnsupportedContract,
    /// Skill identity or version is malformed.
    #[error("skill identity or version is invalid")]
    InvalidIdentity,
    /// Asset/item/byte bounds are invalid.
    #[error("skill manifest bounds are invalid")]
    InvalidBounds,
    /// Asset path, media type, size, or digest is invalid.
    #[error("skill asset evidence is invalid")]
    InvalidAsset,
    /// Two assets claim the same package-relative path.
    #[error("skill asset paths must be unique")]
    DuplicateAsset,
    /// A required tool is not an exact separately governed contract reference.
    #[error("skill tool reference is invalid")]
    InvalidToolReference,
}

fn validate_asset(asset: &SkillAsset) -> Result<(), SkillManifestError> {
    if !safe_relative_path(&asset.relative_path)
        || !valid_media_type(&asset.media_type)
        || !valid_sha256(&asset.content_digest)
        || asset.size_bytes > 16 * 1024 * 1024
    {
        return Err(SkillManifestError::InvalidAsset);
    }
    Ok(())
}

fn safe_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.contains("//")
        && value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
        && !value.chars().any(char::is_control)
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

fn valid_media_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.trim() == value
        && value.contains('/')
        && !value.chars().any(char::is_control)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{
        SKILL_MANIFEST_CONTRACT_VERSION, SkillAsset, SkillManifest, SkillManifestError,
        SkillToolRequirement,
    };
    use std::collections::BTreeSet;

    fn manifest() -> SkillManifest {
        SkillManifest {
            contract_version: SKILL_MANIFEST_CONTRACT_VERSION.to_owned(),
            skill_id: "mealy.fixture.review".to_owned(),
            version: "1.0.0".to_owned(),
            instructions: vec![SkillAsset {
                relative_path: "instructions/review.md".to_owned(),
                media_type: "text/markdown".to_owned(),
                content_digest: "a".repeat(64),
                size_bytes: 128,
            }],
            resources: vec![SkillAsset {
                relative_path: "resources/rubric.json".to_owned(),
                media_type: "application/json".to_owned(),
                content_digest: "b".repeat(64),
                size_bytes: 64,
            }],
            required_tools: BTreeSet::from([SkillToolRequirement {
                tool_id: "fixture.read".to_owned(),
                version: "1".to_owned(),
                input_schema_digest: "c".repeat(64),
            }]),
        }
    }

    #[test]
    fn data_only_skill_requires_pinned_assets_and_separate_tools() {
        manifest().validate().expect("valid skill");
        let mut duplicate = manifest();
        duplicate.resources[0].relative_path = duplicate.instructions[0].relative_path.clone();
        assert_eq!(
            duplicate.validate(),
            Err(SkillManifestError::DuplicateAsset)
        );
        let mut traversal = manifest();
        traversal.instructions[0].relative_path = "../run.sh".to_owned();
        assert_eq!(traversal.validate(), Err(SkillManifestError::InvalidAsset));
    }

    #[test]
    fn executable_helper_fields_are_not_part_of_the_skill_schema() {
        let mut value = serde_json::to_value(manifest()).expect("serialize fixture");
        value
            .as_object_mut()
            .expect("manifest object")
            .insert("executable".to_owned(), serde_json::json!("helpers/run.sh"));
        assert!(serde_json::from_value::<SkillManifest>(value).is_err());
    }
}
