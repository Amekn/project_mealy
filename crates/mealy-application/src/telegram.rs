use crate::{InputAdmissionReceipt, OwnershipContext, is_sha256_digest, valid_provider_secret_id};
use mealy_domain::{ChannelBindingId, CorrelationId, EventId, PrincipalId, SessionId};
use std::time::SystemTime;
use thiserror::Error;

/// Maximum UTF-8 bytes retained from a verified Telegram bot username.
pub const TELEGRAM_MAXIMUM_BOT_USERNAME_BYTES: usize = 64;
/// Maximum safe operator-facing Telegram failure code bytes.
pub const TELEGRAM_MAXIMUM_ERROR_CODE_BYTES: usize = 128;
/// Maximum ignored-update reason bytes.
pub const TELEGRAM_MAXIMUM_IGNORE_REASON_BYTES: usize = 256;

/// Durable lifecycle of one exact Telegram bot/user/chat binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelegramChannelStatus {
    /// Polling, admission, and outbound delivery are authorized.
    Active,
    /// Bot-token authority is terminally revoked while evidence remains.
    Revoked,
}

/// Owner-authorized Telegram channel projection without credential material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelegramChannelBindingView {
    /// Stable verified channel binding.
    pub binding_id: ChannelBindingId,
    /// Local owner principal.
    pub principal_id: PrincipalId,
    /// Dedicated durable conversation session.
    pub session_id: SessionId,
    /// Exact Telegram sender allowlist identity.
    pub telegram_user_id: i64,
    /// Exact Telegram chat allowlist identity.
    pub telegram_chat_id: i64,
    /// Bot identity verified with `getMe` during setup.
    pub bot_user_id: i64,
    /// Bot username verified with `getMe` during setup.
    pub bot_username: String,
    /// Opaque owner-private broker identity.
    pub token_secret_id: String,
    /// Digest pin for the brokered bot token.
    pub token_digest: String,
    /// First not-yet-terminally-processed Telegram update identity.
    pub next_update_id: i64,
    /// Current terminal lifecycle state.
    pub status: TelegramChannelStatus,
    /// Optimistic-concurrency revision for owner lifecycle commands.
    pub revision: u64,
    /// Most recent successful poll time.
    pub last_success_at_ms: Option<i64>,
    /// Most recent failed poll time.
    pub last_failure_at_ms: Option<i64>,
    /// Consecutive bounded poll failures.
    pub consecutive_failures: u64,
    /// Stable secret-free failure code.
    pub last_error_code: Option<String>,
    /// Creation UTC epoch milliseconds.
    pub created_at_ms: i64,
    /// Last lifecycle update UTC epoch milliseconds.
    pub updated_at_ms: i64,
}

/// Atomic Telegram binding, registry, and dedicated-session creation.
pub struct RegisterTelegramChannelCommit {
    /// Authenticated local administrator.
    pub administrative_ownership: OwnershipContext,
    /// New channel binding identity.
    pub binding_id: ChannelBindingId,
    /// New dedicated session identity.
    pub session_id: SessionId,
    /// Exact allowed Telegram sender.
    pub telegram_user_id: i64,
    /// Exact allowed Telegram chat.
    pub telegram_chat_id: i64,
    /// First update the new binding may reserve.
    pub initial_next_update_id: i64,
    /// Verified bot user identity.
    pub bot_user_id: i64,
    /// Verified bot username.
    pub bot_username: String,
    /// Opaque token broker identity.
    pub token_secret_id: String,
    /// SHA-256 digest of the already-brokered token.
    pub token_digest: String,
    /// Canonical `session.created` event.
    pub session_event_id: EventId,
    /// Canonical `channel.telegram_registered` event.
    pub binding_event_id: EventId,
    /// End-to-end setup correlation.
    pub correlation_id: CorrelationId,
    /// Creation time.
    pub created_at: SystemTime,
}

/// Terminal owner-authorized Telegram binding revocation.
pub struct RevokeTelegramChannelCommit {
    /// Authenticated local administrator.
    pub administrative_ownership: OwnershipContext,
    /// Exact binding.
    pub binding_id: ChannelBindingId,
    /// Optimistic-concurrency lifecycle fence.
    pub expected_revision: u64,
    /// Canonical revocation event.
    pub event_id: EventId,
    /// End-to-end command correlation.
    pub correlation_id: CorrelationId,
    /// Revocation time.
    pub revoked_at: SystemTime,
}

/// Durable reservation before one Telegram update can affect a session.
pub struct ReserveTelegramUpdateCommit {
    /// Exact bot binding which fetched the update.
    pub binding_id: ChannelBindingId,
    /// Telegram's monotonically confirmed update identity.
    pub update_id: i64,
    /// Digest of canonical untrusted update JSON.
    pub body_digest: String,
    /// Receipt time.
    pub received_at: SystemTime,
}

/// Result of reserving one exact update identity and body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelegramUpdateReservation {
    /// New durable reservation owned by this processing attempt.
    Reserved,
    /// The same body was reserved before a crash and must resume.
    ExistingReserved,
    /// The same update is already terminal and needs no repeated action.
    ExistingCompleted,
}

/// Terminal result attached to one reserved Telegram update.
pub enum TelegramUpdateDisposition {
    /// Exact idempotent session admission completed.
    Admitted(InputAdmissionReceipt),
    /// The update was deliberately ignored under a stable bounded reason.
    Ignored(String),
}

/// Atomic terminal update evidence and next-poll cursor advancement.
pub struct CompleteTelegramUpdateCommit {
    /// Exact binding.
    pub binding_id: ChannelBindingId,
    /// Reserved Telegram update identity.
    pub update_id: i64,
    /// Terminal admitted or ignored result.
    pub disposition: TelegramUpdateDisposition,
    /// Completion time.
    pub completed_at: SystemTime,
}

/// One durable, secret-free poll health observation.
pub struct RecordTelegramPollCommit {
    /// Exact binding.
    pub binding_id: ChannelBindingId,
    /// Whether the Bot API request and response were valid.
    pub succeeded: bool,
    /// Stable error code on failure; absent on success.
    pub error_code: Option<String>,
    /// Observation time.
    pub observed_at: SystemTime,
}

/// Internal active Telegram target for polling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelegramPollTarget {
    /// Exact channel binding.
    pub binding_id: ChannelBindingId,
    /// Exact allowed sender.
    pub telegram_user_id: i64,
    /// Exact allowed chat.
    pub telegram_chat_id: i64,
    /// Dedicated destination session.
    pub session_id: SessionId,
    /// Effective session owner/channel binding.
    pub ownership: OwnershipContext,
    /// Opaque broker identity.
    pub token_secret_id: String,
    /// Required token digest.
    pub token_digest: String,
    /// First update requested from Telegram.
    pub next_update_id: i64,
}

/// Internal Telegram destination for one existing session outbox notification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundTelegramTarget {
    /// Exact binding.
    pub binding_id: ChannelBindingId,
    /// Exact destination chat.
    pub telegram_chat_id: i64,
    /// Opaque broker identity.
    pub token_secret_id: String,
    /// Required token digest.
    pub token_digest: String,
}

/// Telegram channel administration, update-ledger, and routing persistence failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TelegramChannelStoreError {
    /// Binding is absent or deliberately hidden.
    #[error("Telegram channel was not found")]
    NotFound,
    /// Binding is terminally revoked.
    #[error("Telegram channel is revoked")]
    Revoked,
    /// Revision, update identity, or immutable evidence conflicts.
    #[error("Telegram channel operation conflicts with canonical state")]
    Conflict,
    /// Supplied fields violate the bounded channel contract.
    #[error("Telegram channel contract is invalid: {0}")]
    InvalidContract(String),
    /// Persistence is temporarily unavailable.
    #[error("Telegram channel store is unavailable: {0}")]
    Unavailable(String),
    /// Canonical stored evidence violates an invariant.
    #[error("Telegram channel invariant violation: {0}")]
    InvariantViolation(String),
}

/// Port for Telegram channel administration, polling recovery, and outbox routing.
pub trait TelegramChannelStore {
    /// Creates one exact bot/user/chat binding and dedicated session atomically.
    ///
    /// # Errors
    ///
    /// Returns [`TelegramChannelStoreError`] for invalid, unauthorized, or conflicting state.
    fn register_telegram_channel(
        &mut self,
        commit: RegisterTelegramChannelCommit,
    ) -> Result<TelegramChannelBindingView, TelegramChannelStoreError>;

    /// Terminally revokes one owner-authorized binding.
    ///
    /// # Errors
    ///
    /// Returns [`TelegramChannelStoreError`] for ownership, revision, or lifecycle conflicts.
    fn revoke_telegram_channel(
        &mut self,
        commit: RevokeTelegramChannelCommit,
    ) -> Result<TelegramChannelBindingView, TelegramChannelStoreError>;

    /// Reads one binding through authenticated owner administration.
    ///
    /// # Errors
    ///
    /// Returns [`TelegramChannelStoreError`] when absent, unauthorized, or corrupt.
    fn telegram_channel(
        &self,
        ownership: OwnershipContext,
        binding_id: ChannelBindingId,
    ) -> Result<TelegramChannelBindingView, TelegramChannelStoreError>;

    /// Lists owner-authorized Telegram bindings in stable order.
    ///
    /// # Errors
    ///
    /// Returns [`TelegramChannelStoreError`] for authorization or persistence failure.
    fn telegram_channels(
        &self,
        ownership: OwnershipContext,
    ) -> Result<Vec<TelegramChannelBindingView>, TelegramChannelStoreError>;

    /// Lists a bounded stable batch of active poll targets for the trusted daemon driver.
    ///
    /// # Errors
    ///
    /// Returns [`TelegramChannelStoreError`] for invalid bounds or persistence failure.
    fn active_telegram_poll_targets(
        &self,
        limit: usize,
    ) -> Result<Vec<TelegramPollTarget>, TelegramChannelStoreError>;

    /// Reserves or recovers one exact update before admission.
    ///
    /// # Errors
    ///
    /// Returns [`TelegramChannelStoreError`] for conflicting body or inactive authority.
    fn reserve_telegram_update(
        &mut self,
        commit: ReserveTelegramUpdateCommit,
    ) -> Result<TelegramUpdateReservation, TelegramChannelStoreError>;

    /// Commits terminal update evidence and advances the poll cursor atomically.
    ///
    /// # Errors
    ///
    /// Returns [`TelegramChannelStoreError`] for invalid receipt, stale state, or persistence.
    fn complete_telegram_update(
        &mut self,
        commit: CompleteTelegramUpdateCommit,
    ) -> Result<(), TelegramChannelStoreError>;

    /// Records secret-free current health for operator diagnostics.
    ///
    /// # Errors
    ///
    /// Returns [`TelegramChannelStoreError`] for malformed codes, inactive state, or persistence.
    fn record_telegram_poll(
        &mut self,
        commit: RecordTelegramPollCommit,
    ) -> Result<(), TelegramChannelStoreError>;

    /// Resolves an active Telegram destination for a supported session outbox topic.
    ///
    /// # Errors
    ///
    /// Returns [`TelegramChannelStoreError`] when routing evidence is corrupt.
    fn outbound_telegram_target(
        &self,
        session_id: SessionId,
        topic: &str,
    ) -> Result<Option<OutboundTelegramTarget>, TelegramChannelStoreError>;
}

/// Validates all non-secret Telegram binding fields and credential evidence.
///
/// # Errors
///
/// Returns [`TelegramChannelStoreError::InvalidContract`] for any malformed value.
pub fn validate_telegram_binding(
    telegram_user_id: i64,
    telegram_chat_id: i64,
    bot_user_id: i64,
    bot_username: &str,
    token_secret_id: &str,
    token_digest: &str,
) -> Result<(), TelegramChannelStoreError> {
    let username_valid = !bot_username.is_empty()
        && bot_username.len() <= TELEGRAM_MAXIMUM_BOT_USERNAME_BYTES
        && bot_username.trim() == bot_username
        && bot_username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    if telegram_user_id <= 0
        || telegram_chat_id == 0
        || bot_user_id <= 0
        || !username_valid
        || !valid_provider_secret_id(token_secret_id)
        || !is_sha256_digest(token_digest)
    {
        Err(TelegramChannelStoreError::InvalidContract(
            "Telegram identity or credential evidence is invalid".to_owned(),
        ))
    } else {
        Ok(())
    }
}

/// Stable session idempotency key for one Telegram update.
///
/// # Errors
///
/// Returns [`TelegramChannelStoreError::InvalidContract`] for a negative update identity.
pub fn telegram_input_dedupe_key(
    binding_id: ChannelBindingId,
    update_id: i64,
) -> Result<String, TelegramChannelStoreError> {
    if update_id < 0 {
        Err(TelegramChannelStoreError::InvalidContract(
            "Telegram update identity is invalid".to_owned(),
        ))
    } else {
        Ok(format!("telegram:{binding_id}:{update_id}"))
    }
}
