use crate::{CancellationProbe, is_sha256_digest, sha256_digest};
use mealy_domain::{AttemptId, EffectId, FencingToken, PolicyProfile};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Version of the one-shot, provider-neutral executor protocol.
pub const EXECUTOR_PROTOCOL_VERSION: &str = "mealy.executor.v1";

const MAXIMUM_ARGUMENT_BYTES: usize = 64 * 1024;
const MAXIMUM_CAPABILITY_TOKEN_BYTES: usize = 512;
const MAXIMUM_FIELD_BYTES: usize = 512;
const MAXIMUM_MOUNTS: usize = 32;
const MAXIMUM_ENVIRONMENT_VARIABLES: usize = 64;
const MAXIMUM_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
const MAXIMUM_DURATION_MS: u64 = 60 * 60 * 1_000;
const MAXIMUM_MEMORY_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAXIMUM_PROCESSES: u32 = 1_024;

/// One host directory exposed at one absolute path inside an executor sandbox.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutorMount {
    /// Absolute host directory selected by trusted policy code.
    pub host_path: String,
    /// Absolute, normalized path at which the directory appears to the worker.
    pub sandbox_path: String,
}

/// Complete, one-use dispatch request supplied to an isolated executor adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutorRequest {
    /// Exact protocol version understood by both adapter and worker.
    pub protocol_version: String,
    /// Durable effect whose operation is being attempted.
    pub effect_id: EffectId,
    /// Distinct bounded dispatch attempt.
    pub attempt_id: AttemptId,
    /// Lease token that must still fence any later durable result commit.
    pub fencing_token: FencingToken,
    /// Opaque, one-use capability presented only to this worker invocation.
    pub capability_token: String,
    /// SHA-256 identity of the exact trusted worker executable.
    pub executable_identity_digest: String,
    /// OS isolation profile policy requires the adapter to enforce.
    pub profile: PolicyProfile,
    /// Canonically ordered host roots exposed read-only.
    pub readable_roots: Vec<ExecutorMount>,
    /// Canonically ordered host roots exposed read-write.
    pub writable_roots: Vec<ExecutorMount>,
    /// Canonically ordered outbound destinations requested by policy.
    pub network_destinations: Vec<String>,
    /// Canonically ordered opaque secret handles; never secret values.
    pub secret_handles: Vec<String>,
    /// Whether the worker may create child processes.
    pub allow_process_spawn: bool,
    /// Canonically ordered environment variable names policy permits the adapter to supply.
    pub allowed_environment_variables: Vec<String>,
    /// Stable downstream idempotency key when the operation declares one.
    pub idempotency_key: Option<String>,
    /// Schema-validated, provider-neutral operation arguments.
    pub normalized_arguments: serde_json::Value,
    /// SHA-256 digest of canonical normalized arguments.
    pub arguments_digest: String,
    /// Hard wall-clock bound for the worker process.
    pub maximum_duration_ms: u64,
    /// Hard aggregate stdout-frame bound for the worker process.
    pub maximum_output_bytes: u64,
    /// Hard virtual-address-space bound for the worker and its descendants.
    pub maximum_memory_bytes: u64,
    /// Maximum child processes the worker may create, excluding the worker itself.
    pub maximum_processes: u32,
}

impl ExecutorRequest {
    /// Validates canonical request shape before any process or sandbox is created.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorRequestError`] for malformed, unbounded, or internally inconsistent
    /// dispatch evidence.
    pub fn validate(&self) -> Result<(), ExecutorRequestError> {
        if self.protocol_version != EXECUTOR_PROTOCOL_VERSION {
            return Err(ExecutorRequestError::UnsupportedProtocol);
        }
        validate_field(&self.capability_token, 32, MAXIMUM_CAPABILITY_TOKEN_BYTES)
            .map_err(|()| ExecutorRequestError::InvalidCapabilityToken)?;
        if !is_sha256_digest(&self.executable_identity_digest) {
            return Err(ExecutorRequestError::InvalidExecutableIdentityDigest);
        }
        if self.maximum_duration_ms == 0 || self.maximum_duration_ms > MAXIMUM_DURATION_MS {
            return Err(ExecutorRequestError::InvalidDurationLimit);
        }
        if self.maximum_output_bytes == 0 || self.maximum_output_bytes > MAXIMUM_OUTPUT_BYTES {
            return Err(ExecutorRequestError::InvalidOutputLimit);
        }
        validate_mounts(&self.readable_roots)?;
        validate_mounts(&self.writable_roots)?;
        let all_mounts = self
            .readable_roots
            .iter()
            .chain(&self.writable_roots)
            .collect::<Vec<_>>();
        if all_mounts.iter().enumerate().any(|(index, mount)| {
            all_mounts.iter().skip(index + 1).any(|other| {
                paths_overlap(&mount.host_path, &other.host_path)
                    || paths_overlap(&mount.sandbox_path, &other.sandbox_path)
            })
        }) {
            return Err(ExecutorRequestError::DuplicateMount);
        }
        validate_canonical_set(&self.network_destinations, false)?;
        validate_canonical_set(&self.secret_handles, false)?;
        validate_environment_variables(&self.allowed_environment_variables)?;
        if self.maximum_memory_bytes == 0 || self.maximum_memory_bytes > MAXIMUM_MEMORY_BYTES {
            return Err(ExecutorRequestError::InvalidMemoryLimit);
        }
        if self.maximum_processes > MAXIMUM_PROCESSES
            || self.allow_process_spawn != (self.maximum_processes > 0)
        {
            return Err(ExecutorRequestError::InvalidProcessLimit);
        }
        if let Some(key) = &self.idempotency_key {
            validate_field(key, 1, MAXIMUM_FIELD_BYTES)
                .map_err(|()| ExecutorRequestError::InvalidIdempotencyKey)?;
        }
        let arguments = serde_json::to_string(&self.normalized_arguments)
            .map_err(|_| ExecutorRequestError::InvalidArguments)?;
        if arguments.len() > MAXIMUM_ARGUMENT_BYTES
            || sha256_digest(arguments.as_bytes()) != self.arguments_digest
        {
            return Err(ExecutorRequestError::InvalidArguments);
        }
        Ok(())
    }

    /// Returns the digest echoed by the worker instead of the raw one-use token.
    #[must_use]
    pub fn capability_token_digest(&self) -> String {
        sha256_digest(self.capability_token.as_bytes())
    }

    /// Returns a digest binding every serialized request field without exposing the capability.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorRequestError::InvalidArguments`] if the normalized request cannot be
    /// encoded as canonical JSON.
    pub fn evidence_digest(&self) -> Result<String, ExecutorRequestError> {
        serde_json::to_vec(self)
            .map(|encoded| sha256_digest(&encoded))
            .map_err(|_| ExecutorRequestError::InvalidArguments)
    }
}

/// Structured terminal outcome emitted by a one-shot worker.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ExecutorTerminal {
    /// Operation completed and returned canonical provider-neutral output.
    Succeeded {
        /// Schema-normalized operation result.
        output: serde_json::Value,
        /// SHA-256 digest of canonical `output` JSON.
        output_digest: String,
    },
    /// Worker rejected or failed the operation without crashing the protocol boundary.
    Failed {
        /// Stable, bounded failure class.
        error_class: String,
        /// Sanitized, bounded failure explanation.
        error_message: String,
        /// Whether the tool contract permits a new durable attempt.
        retryable: bool,
    },
}

/// One newline-delimited frame from the isolated one-shot worker.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "frameType", rename_all = "snake_case")]
pub enum ExecutorFrame {
    /// First frame, proving the worker received the exact dispatch boundary.
    Started {
        /// Exact protocol version understood by the worker.
        protocol_version: String,
        /// Contiguous frame sequence, always zero for this variant.
        sequence: u64,
        /// Effect copied from the dispatch request.
        effect_id: EffectId,
        /// Attempt copied from the dispatch request.
        attempt_id: AttemptId,
        /// Fence copied from the dispatch request.
        fencing_token: FencingToken,
        /// Digest of the one-use token, never the token itself.
        capability_token_digest: String,
        /// Digest of the exact executable identity authorized by policy.
        executable_identity_digest: String,
        /// Digest binding every field of the canonical dispatch request.
        request_evidence_digest: String,
    },
    /// Optional bounded, non-terminal worker progress.
    Progress {
        /// Contiguous frame sequence.
        sequence: u64,
        /// Sanitized bounded progress message.
        message: String,
    },
    /// Final structured result; no frame may follow it.
    Terminal {
        /// Contiguous frame sequence.
        sequence: u64,
        /// Exact success or classified failure outcome.
        outcome: ExecutorTerminal,
    },
}

impl ExecutorFrame {
    /// Returns the contiguous sequence carried by this frame.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        match self {
            Self::Started { sequence, .. }
            | Self::Progress { sequence, .. }
            | Self::Terminal { sequence, .. } => *sequence,
        }
    }
}

/// Validated terminal result returned by an executor adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutorResult {
    /// Exact validated frame stream retained for durable evidence.
    pub frames: Vec<ExecutorFrame>,
    /// Terminal result cloned from the last validated frame.
    pub terminal: ExecutorTerminal,
    /// Observed worker duration in whole milliseconds.
    pub duration_ms: u64,
}

impl ExecutorResult {
    /// Constructs a result only from a complete, request-bound frame stream.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorProtocolError`] for a missing, reordered, forged, or malformed semantic
    /// frame.
    pub fn from_frames(
        request: &ExecutorRequest,
        frames: Vec<ExecutorFrame>,
        duration_ms: u64,
    ) -> Result<Self, ExecutorProtocolError> {
        if duration_ms > request.maximum_duration_ms {
            return Err(ExecutorProtocolError::DurationExceeded);
        }
        let Some(ExecutorFrame::Started {
            protocol_version,
            sequence,
            effect_id,
            attempt_id,
            fencing_token,
            capability_token_digest,
            executable_identity_digest,
            request_evidence_digest,
        }) = frames.first()
        else {
            return Err(ExecutorProtocolError::MissingStart);
        };
        if protocol_version != EXECUTOR_PROTOCOL_VERSION
            || *sequence != 0
            || *effect_id != request.effect_id
            || *attempt_id != request.attempt_id
            || *fencing_token != request.fencing_token
            || capability_token_digest != &request.capability_token_digest()
            || executable_identity_digest != &request.executable_identity_digest
            || request_evidence_digest
                != &request
                    .evidence_digest()
                    .map_err(|_| ExecutorProtocolError::StartMismatch)?
        {
            return Err(ExecutorProtocolError::StartMismatch);
        }
        if frames
            .iter()
            .enumerate()
            .any(|(index, frame)| u64::try_from(index).ok() != Some(frame.sequence()))
        {
            return Err(ExecutorProtocolError::NonContiguousSequence);
        }
        for frame in frames.iter().skip(1).take(frames.len().saturating_sub(2)) {
            match frame {
                ExecutorFrame::Progress { message, .. } => validate_field(message, 1, 4_096)
                    .map_err(|()| ExecutorProtocolError::InvalidProgress)?,
                ExecutorFrame::Started { .. } | ExecutorFrame::Terminal { .. } => {
                    return Err(ExecutorProtocolError::UnexpectedFrame);
                }
            }
        }
        let Some(ExecutorFrame::Terminal { outcome, .. }) = frames.last() else {
            return Err(ExecutorProtocolError::MissingTerminal);
        };
        validate_terminal(outcome)?;
        let terminal = outcome.clone();
        Ok(Self {
            frames,
            terminal,
            duration_ms,
        })
    }
}

/// Invalid shape detected before an executor is dispatched.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ExecutorRequestError {
    /// Protocol version is not supported by this runtime.
    #[error("executor protocol version is unsupported")]
    UnsupportedProtocol,
    /// Capability token is empty, oversized, or non-canonical.
    #[error("executor capability token is invalid")]
    InvalidCapabilityToken,
    /// Executable identity is not a canonical SHA-256 digest.
    #[error("executor executable identity digest is invalid")]
    InvalidExecutableIdentityDigest,
    /// Requested duration is zero or outside the application bound.
    #[error("executor duration limit is invalid")]
    InvalidDurationLimit,
    /// Requested output is zero or outside the application bound.
    #[error("executor output limit is invalid")]
    InvalidOutputLimit,
    /// A mount path is relative, non-normalized, duplicated, or unbounded.
    #[error("executor mount declaration is invalid")]
    InvalidMount,
    /// A root was granted both read-only and read-write access.
    #[error("executor mount declaration is duplicated")]
    DuplicateMount,
    /// A canonical string set is malformed or not strictly sorted.
    #[error("executor canonical string set is invalid")]
    InvalidCanonicalSet,
    /// Stable downstream key is malformed or unbounded.
    #[error("executor idempotency key is invalid")]
    InvalidIdempotencyKey,
    /// Allowed environment variable names are malformed or non-canonical.
    #[error("executor environment variable names are invalid")]
    InvalidEnvironmentVariables,
    /// Virtual-address-space bound is zero or outside the protocol maximum.
    #[error("executor memory limit is invalid")]
    InvalidMemoryLimit,
    /// Child-process permission and count are inconsistent or outside the protocol maximum.
    #[error("executor process limit is invalid")]
    InvalidProcessLimit,
    /// Arguments are unencodable, oversized, or do not match their digest.
    #[error("executor normalized arguments are invalid")]
    InvalidArguments,
}

/// Malformed or request-divergent worker protocol evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ExecutorProtocolError {
    /// Stream did not begin with a start frame.
    #[error("executor frame stream has no start frame")]
    MissingStart,
    /// Start frame does not bind the exact request.
    #[error("executor start frame does not match the request")]
    StartMismatch,
    /// Frame sequences are not contiguous from zero.
    #[error("executor frame sequence is not contiguous")]
    NonContiguousSequence,
    /// A second start or early terminal frame violated the protocol phase grammar.
    #[error("executor emitted a frame in an invalid protocol phase")]
    UnexpectedFrame,
    /// Progress text is empty or outside its bound.
    #[error("executor progress frame is invalid")]
    InvalidProgress,
    /// Stream ended without one terminal frame.
    #[error("executor frame stream has no terminal frame")]
    MissingTerminal,
    /// Terminal output or failure evidence is malformed.
    #[error("executor terminal frame is invalid")]
    InvalidTerminal,
    /// Claimed result duration exceeded the exact request limit.
    #[error("executor result duration exceeded the request limit")]
    DurationExceeded,
}

/// Failure at the provider-neutral isolated executor boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ExecutorError {
    /// Dispatch request failed deterministic validation.
    #[error("invalid executor request: {0}")]
    InvalidRequest(ExecutorRequestError),
    /// Host or installed sandbox backend cannot enforce the requested boundary.
    #[error("sandbox host capability is unsupported: {0}")]
    UnsupportedHost(String),
    /// Available backend cannot faithfully enforce this policy profile.
    #[error("sandbox profile is unsupported: {0:?}")]
    UnsupportedProfile(PolicyProfile),
    /// Trusted worker bytes do not match policy and adapter identity evidence.
    #[error("sandbox worker executable identity does not match")]
    ExecutableIdentityMismatch,
    /// A one-use capability token was already consumed.
    #[error("sandbox capability token was already consumed")]
    CapabilityAlreadyUsed,
    /// Worker protocol output exceeded its aggregate or per-frame bound.
    #[error("sandbox worker output exceeded its bound")]
    OutputLimitExceeded,
    /// Worker emitted bytes that were not one canonical structured frame per line.
    #[error("sandbox worker emitted a malformed frame")]
    MalformedFrame,
    /// Structured frames did not form a complete request-bound stream.
    #[error("invalid executor frame protocol: {0}")]
    Protocol(ExecutorProtocolError),
    /// Worker exceeded its hard duration limit and was killed.
    #[error("sandbox worker exceeded its duration limit")]
    TimedOut,
    /// Cancellation was observed and the worker was killed.
    #[error("sandbox worker was cancelled")]
    Cancelled,
    /// Worker or sandbox backend exited without a valid terminal result.
    #[error("sandbox worker crashed with exit code {0:?}")]
    WorkerCrashed(Option<i32>),
    /// Process, pipe, or host filesystem operation failed.
    #[error("sandbox executor I/O failed: {0}")]
    Io(String),
}

/// Port for one-shot, policy-bound OS-isolated tool execution.
pub trait SandboxExecutor: Send + Sync + 'static {
    /// Executes one exact request without granting ambient daemon authority.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError`] when validation, containment, protocol, cancellation, or the
    /// worker process fails.
    fn execute(
        &self,
        request: &ExecutorRequest,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ExecutorResult, ExecutorError>;
}

fn validate_mounts(mounts: &[ExecutorMount]) -> Result<(), ExecutorRequestError> {
    if mounts.len() > MAXIMUM_MOUNTS
        || mounts.windows(2).any(|pair| pair[0] >= pair[1])
        || mounts.iter().any(|mount| {
            !canonical_absolute_path(&mount.host_path)
                || !canonical_absolute_path(&mount.sandbox_path)
                || reserved_sandbox_path(&mount.sandbox_path)
        })
    {
        Err(ExecutorRequestError::InvalidMount)
    } else {
        Ok(())
    }
}

fn canonical_absolute_path(value: &str) -> bool {
    value.len() >= 2
        && value.len() <= 4_096
        && value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains('\0')
        && value
            .split('/')
            .skip(1)
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn reserved_sandbox_path(value: &str) -> bool {
    ["/dev", "/proc", "/runtime", "/tmp"]
        .iter()
        .any(|reserved| value == *reserved || value.starts_with(&format!("{reserved}/")))
}

fn paths_overlap(left: &str, right: &str) -> bool {
    left == right
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || left
            .strip_prefix(right)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn validate_canonical_set(values: &[String], required: bool) -> Result<(), ExecutorRequestError> {
    if required && values.is_empty()
        || values.len() > 64
        || values.windows(2).any(|pair| pair[0] >= pair[1])
        || values
            .iter()
            .any(|value| validate_field(value, 1, MAXIMUM_FIELD_BYTES).is_err())
    {
        Err(ExecutorRequestError::InvalidCanonicalSet)
    } else {
        Ok(())
    }
}

fn validate_environment_variables(values: &[String]) -> Result<(), ExecutorRequestError> {
    if values.len() > MAXIMUM_ENVIRONMENT_VARIABLES
        || values.windows(2).any(|pair| pair[0] >= pair[1])
        || values.iter().any(|value| {
            value.len() > 128
                || value.is_empty()
                || !value.bytes().enumerate().all(|(index, byte)| {
                    byte == b'_' || byte.is_ascii_alphabetic() || index > 0 && byte.is_ascii_digit()
                })
        })
    {
        Err(ExecutorRequestError::InvalidEnvironmentVariables)
    } else {
        Ok(())
    }
}

fn validate_field(value: &str, minimum: usize, maximum: usize) -> Result<(), ()> {
    if value.len() < minimum
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        Err(())
    } else {
        Ok(())
    }
}

fn validate_terminal(terminal: &ExecutorTerminal) -> Result<(), ExecutorProtocolError> {
    match terminal {
        ExecutorTerminal::Succeeded {
            output,
            output_digest,
        } => {
            let encoded = serde_json::to_string(output)
                .map_err(|_| ExecutorProtocolError::InvalidTerminal)?;
            if !is_sha256_digest(output_digest)
                || sha256_digest(encoded.as_bytes()) != *output_digest
            {
                return Err(ExecutorProtocolError::InvalidTerminal);
            }
        }
        ExecutorTerminal::Failed {
            error_class,
            error_message,
            ..
        } => {
            validate_field(error_class, 1, 128)
                .and_then(|()| validate_field(error_message, 1, 4_096))
                .map_err(|()| ExecutorProtocolError::InvalidTerminal)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        EXECUTOR_PROTOCOL_VERSION, ExecutorFrame, ExecutorMount, ExecutorProtocolError,
        ExecutorRequest, ExecutorRequestError, ExecutorResult, ExecutorTerminal,
    };
    use crate::sha256_digest;
    use mealy_domain::{AttemptId, EffectId, FencingToken, PolicyProfile};

    fn request() -> ExecutorRequest {
        let arguments = serde_json::json!({"operation": "probe_isolation"});
        ExecutorRequest {
            protocol_version: EXECUTOR_PROTOCOL_VERSION.to_owned(),
            effect_id: EffectId::new(),
            attempt_id: AttemptId::new(),
            fencing_token: FencingToken::new(1).expect("nonzero fence"),
            capability_token: "a-valid-one-use-capability-token".to_owned(),
            executable_identity_digest: sha256_digest(b"worker"),
            profile: PolicyProfile::Observe,
            readable_roots: vec![ExecutorMount {
                host_path: "/host/input".to_owned(),
                sandbox_path: "/inputs/fixture".to_owned(),
            }],
            writable_roots: Vec::new(),
            network_destinations: Vec::new(),
            secret_handles: Vec::new(),
            allow_process_spawn: false,
            allowed_environment_variables: Vec::new(),
            idempotency_key: None,
            normalized_arguments: arguments.clone(),
            arguments_digest: sha256_digest(arguments.to_string().as_bytes()),
            maximum_duration_ms: 1_000,
            maximum_output_bytes: 4_096,
            maximum_memory_bytes: 256 * 1024 * 1024,
            maximum_processes: 0,
        }
    }

    fn frames(request: &ExecutorRequest) -> Vec<ExecutorFrame> {
        let output = serde_json::json!({"isolated": true});
        vec![
            ExecutorFrame::Started {
                protocol_version: EXECUTOR_PROTOCOL_VERSION.to_owned(),
                sequence: 0,
                effect_id: request.effect_id,
                attempt_id: request.attempt_id,
                fencing_token: request.fencing_token,
                capability_token_digest: request.capability_token_digest(),
                executable_identity_digest: request.executable_identity_digest.clone(),
                request_evidence_digest: request.evidence_digest().expect("encodable request"),
            },
            ExecutorFrame::Terminal {
                sequence: 1,
                outcome: ExecutorTerminal::Succeeded {
                    output: output.clone(),
                    output_digest: sha256_digest(output.to_string().as_bytes()),
                },
            },
        ]
    }

    #[test]
    fn request_binds_canonical_arguments_and_mounts() {
        let mut candidate = request();
        candidate.validate().expect("valid request");
        candidate.arguments_digest = sha256_digest(b"forged");
        assert_eq!(
            candidate.validate(),
            Err(ExecutorRequestError::InvalidArguments)
        );

        let mut candidate = request();
        candidate.readable_roots[0].sandbox_path = "/inputs/../escape".to_owned();
        assert_eq!(
            candidate.validate(),
            Err(ExecutorRequestError::InvalidMount)
        );
    }

    #[test]
    fn request_binds_environment_memory_and_process_obligations() {
        let mut candidate = request();
        candidate.allowed_environment_variables = vec!["VALID".to_owned(), "1INVALID".to_owned()];
        assert_eq!(
            candidate.validate(),
            Err(ExecutorRequestError::InvalidEnvironmentVariables)
        );

        let mut candidate = request();
        candidate.maximum_memory_bytes = 0;
        assert_eq!(
            candidate.validate(),
            Err(ExecutorRequestError::InvalidMemoryLimit)
        );

        let mut candidate = request();
        candidate.allow_process_spawn = true;
        assert_eq!(
            candidate.validate(),
            Err(ExecutorRequestError::InvalidProcessLimit)
        );
    }

    #[test]
    fn result_requires_exact_request_binding_and_sequence() {
        let request = request();
        let valid = frames(&request);
        ExecutorResult::from_frames(&request, valid.clone(), 1).expect("valid frame stream");

        let mut reordered = valid;
        if let ExecutorFrame::Terminal { sequence, .. } = &mut reordered[1] {
            *sequence = 2;
        }
        assert_eq!(
            ExecutorResult::from_frames(&request, reordered, 1),
            Err(ExecutorProtocolError::NonContiguousSequence)
        );

        let mut duplicate_start = frames(&request);
        duplicate_start.insert(1, duplicate_start[0].clone());
        if let ExecutorFrame::Started { sequence, .. } = &mut duplicate_start[1] {
            *sequence = 1;
        }
        if let ExecutorFrame::Terminal { sequence, .. } = &mut duplicate_start[2] {
            *sequence = 2;
        }
        assert_eq!(
            ExecutorResult::from_frames(&request, duplicate_start, 1),
            Err(ExecutorProtocolError::UnexpectedFrame)
        );
        assert_eq!(
            ExecutorResult::from_frames(&request, frames(&request), 1_001),
            Err(ExecutorProtocolError::DurationExceeded)
        );
    }

    #[test]
    fn request_rejects_overlapping_mount_authority() {
        let mut request = request();
        request.writable_roots.push(ExecutorMount {
            host_path: "/host/input/subdirectory".to_owned(),
            sandbox_path: "/workspace".to_owned(),
        });
        assert_eq!(
            request.validate(),
            Err(ExecutorRequestError::DuplicateMount)
        );
    }
}
