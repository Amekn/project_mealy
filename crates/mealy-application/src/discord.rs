use crate::{InputAdmissionReceipt, OwnershipContext, is_sha256_digest, valid_provider_secret_id};
use mealy_domain::{ChannelBindingId, CorrelationId, EventId, PrincipalId, SessionId};
use std::time::SystemTime;
use thiserror::Error;

/// Maximum UTF-8 bytes retained from a verified Discord bot username.
pub const DISCORD_MAXIMUM_BOT_USERNAME_BYTES: usize = 64;
/// Maximum safe operator-facing Discord failure code bytes.
pub const DISCORD_MAXIMUM_ERROR_CODE_BYTES: usize = 128;
/// Maximum ignored-message reason bytes.
pub const DISCORD_MAXIMUM_IGNORE_REASON_BYTES: usize = 256;

/// Durable lifecycle of one exact Discord bot/human/direct-message binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscordChannelStatus {
    /// Polling, admission, and outbound delivery are authorized.
    Active,
    /// Bot-token authority is terminally revoked while evidence remains.
    Revoked,
}

/// Owner-authorized Discord DM projection without credential material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscordChannelBindingView {
    /// Stable verified channel binding.
    pub binding_id: ChannelBindingId,
    /// Local owner principal.
    pub principal_id: PrincipalId,
    /// Dedicated durable conversation session.
    pub session_id: SessionId,
    /// Exact allowed Discord human user snowflake.
    pub discord_user_id: String,
    /// Exact one-to-one Discord DM channel snowflake.
    pub discord_channel_id: String,
    /// Verified Discord bot user snowflake.
    pub bot_user_id: String,
    /// Verified Discord bot username.
    pub bot_username: String,
    /// Opaque owner-private broker identity.
    pub token_secret_id: String,
    /// Digest pin for the brokered bot token.
    pub token_digest: String,
    /// Last terminally processed Discord message identity, if any.
    pub after_message_id: Option<String>,
    /// Current terminal lifecycle state.
    pub status: DiscordChannelStatus,
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

/// Atomic Discord DM binding, registry, and dedicated-session creation.
pub struct RegisterDiscordChannelCommit {
    /// Authenticated local administrator.
    pub administrative_ownership: OwnershipContext,
    /// New channel binding identity.
    pub binding_id: ChannelBindingId,
    /// New dedicated session identity.
    pub session_id: SessionId,
    /// Exact allowed human user snowflake.
    pub discord_user_id: String,
    /// Exact one-to-one DM channel snowflake.
    pub discord_channel_id: String,
    /// Initial last-seen message, sampled after setup verification.
    pub initial_after_message_id: Option<String>,
    /// Verified bot user snowflake.
    pub bot_user_id: String,
    /// Verified bot username.
    pub bot_username: String,
    /// Opaque token broker identity.
    pub token_secret_id: String,
    /// SHA-256 digest of the already-brokered token.
    pub token_digest: String,
    /// Canonical `session.created` event.
    pub session_event_id: EventId,
    /// Canonical `channel.discord_registered` event.
    pub binding_event_id: EventId,
    /// End-to-end setup correlation.
    pub correlation_id: CorrelationId,
    /// Creation time.
    pub created_at: SystemTime,
}

/// Terminal owner-authorized Discord binding revocation.
pub struct RevokeDiscordChannelCommit {
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

/// Durable reservation before one Discord message can affect a session.
pub struct ReserveDiscordMessageCommit {
    /// Exact DM binding which fetched the message.
    pub binding_id: ChannelBindingId,
    /// Discord message snowflake.
    pub message_id: String,
    /// Digest of canonical untrusted message JSON.
    pub body_digest: String,
    /// Receipt time.
    pub received_at: SystemTime,
}

/// Result of reserving one exact message identity and body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscordMessageReservation {
    /// New durable reservation owned by this processing attempt.
    Reserved,
    /// The same body was reserved before a crash and must resume.
    ExistingReserved,
    /// The same message is already terminal and needs no repeated action.
    ExistingCompleted,
}

/// Terminal result attached to one reserved Discord message.
pub enum DiscordMessageDisposition {
    /// Exact idempotent session admission completed.
    Admitted(InputAdmissionReceipt),
    /// The message was deliberately ignored under a stable bounded reason.
    Ignored(String),
}

/// Atomic terminal message evidence and after-cursor advancement.
pub struct CompleteDiscordMessageCommit {
    /// Exact binding.
    pub binding_id: ChannelBindingId,
    /// Reserved Discord message snowflake.
    pub message_id: String,
    /// Terminal admitted or ignored result.
    pub disposition: DiscordMessageDisposition,
    /// Completion time.
    pub completed_at: SystemTime,
}

/// One durable, secret-free poll health observation.
pub struct RecordDiscordPollCommit {
    /// Exact binding.
    pub binding_id: ChannelBindingId,
    /// Whether the Discord request and response were valid.
    pub succeeded: bool,
    /// Stable error code on failure; absent on success.
    pub error_code: Option<String>,
    /// Observation time.
    pub observed_at: SystemTime,
}

/// Internal active Discord DM target for polling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscordPollTarget {
    /// Exact channel binding.
    pub binding_id: ChannelBindingId,
    /// Exact allowed human user snowflake.
    pub discord_user_id: String,
    /// Exact DM channel snowflake.
    pub discord_channel_id: String,
    /// Verified bot user snowflake.
    pub bot_user_id: String,
    /// Dedicated destination session.
    pub session_id: SessionId,
    /// Effective session owner/channel binding.
    pub ownership: OwnershipContext,
    /// Opaque broker identity.
    pub token_secret_id: String,
    /// Required token digest.
    pub token_digest: String,
    /// Last terminal message requested as the exclusive `after` cursor.
    pub after_message_id: Option<String>,
}

/// Internal Discord destination for one existing session outbox notification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundDiscordTarget {
    /// Exact binding.
    pub binding_id: ChannelBindingId,
    /// Exact DM channel snowflake.
    pub discord_channel_id: String,
    /// Verified bot user snowflake.
    pub bot_user_id: String,
    /// Opaque broker identity.
    pub token_secret_id: String,
    /// Required token digest.
    pub token_digest: String,
}

/// Discord channel administration, message-ledger, and routing persistence failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DiscordChannelStoreError {
    /// Binding is absent or deliberately hidden.
    #[error("Discord channel was not found")]
    NotFound,
    /// Binding is terminally revoked.
    #[error("Discord channel is revoked")]
    Revoked,
    /// Revision, message identity, or immutable evidence conflicts.
    #[error("Discord channel operation conflicts with canonical state")]
    Conflict,
    /// Supplied fields violate the bounded channel contract.
    #[error("Discord channel contract is invalid: {0}")]
    InvalidContract(String),
    /// Persistence is temporarily unavailable.
    #[error("Discord channel store is unavailable: {0}")]
    Unavailable(String),
    /// Canonical stored evidence violates an invariant.
    #[error("Discord channel invariant violation: {0}")]
    InvariantViolation(String),
}

/// Port for Discord DM administration, polling recovery, and outbox routing.
pub trait DiscordChannelStore {
    /// Creates one exact bot/human/DM binding and dedicated session atomically.
    ///
    /// # Errors
    ///
    /// Returns [`DiscordChannelStoreError`] for invalid, unauthorized, or conflicting state.
    fn register_discord_channel(
        &mut self,
        commit: RegisterDiscordChannelCommit,
    ) -> Result<DiscordChannelBindingView, DiscordChannelStoreError>;

    /// Terminally revokes one owner-authorized binding.
    ///
    /// # Errors
    ///
    /// Returns [`DiscordChannelStoreError`] for ownership, revision, or lifecycle conflicts.
    fn revoke_discord_channel(
        &mut self,
        commit: RevokeDiscordChannelCommit,
    ) -> Result<DiscordChannelBindingView, DiscordChannelStoreError>;

    /// Reads one binding through authenticated owner administration.
    ///
    /// # Errors
    ///
    /// Returns [`DiscordChannelStoreError`] when absent, unauthorized, or corrupt.
    fn discord_channel(
        &self,
        ownership: OwnershipContext,
        binding_id: ChannelBindingId,
    ) -> Result<DiscordChannelBindingView, DiscordChannelStoreError>;

    /// Lists owner-authorized Discord bindings in stable order.
    ///
    /// # Errors
    ///
    /// Returns [`DiscordChannelStoreError`] for authorization or persistence failure.
    fn discord_channels(
        &self,
        ownership: OwnershipContext,
    ) -> Result<Vec<DiscordChannelBindingView>, DiscordChannelStoreError>;

    /// Lists a bounded stable batch of active DM poll targets.
    ///
    /// # Errors
    ///
    /// Returns [`DiscordChannelStoreError`] for invalid bounds or persistence failure.
    fn active_discord_poll_targets(
        &self,
        limit: usize,
    ) -> Result<Vec<DiscordPollTarget>, DiscordChannelStoreError>;

    /// Reserves or recovers one exact message before admission.
    ///
    /// # Errors
    ///
    /// Returns [`DiscordChannelStoreError`] for conflicting bodies or inactive authority.
    fn reserve_discord_message(
        &mut self,
        commit: ReserveDiscordMessageCommit,
    ) -> Result<DiscordMessageReservation, DiscordChannelStoreError>;

    /// Commits terminal message evidence and advances the after cursor atomically.
    ///
    /// # Errors
    ///
    /// Returns [`DiscordChannelStoreError`] for invalid receipts, stale state, or persistence.
    fn complete_discord_message(
        &mut self,
        commit: CompleteDiscordMessageCommit,
    ) -> Result<(), DiscordChannelStoreError>;

    /// Records secret-free current health for operator diagnostics.
    ///
    /// # Errors
    ///
    /// Returns [`DiscordChannelStoreError`] for malformed codes, inactive state, or persistence.
    fn record_discord_poll(
        &mut self,
        commit: RecordDiscordPollCommit,
    ) -> Result<(), DiscordChannelStoreError>;

    /// Resolves an active Discord destination for a supported session outbox topic.
    ///
    /// # Errors
    ///
    /// Returns [`DiscordChannelStoreError`] when routing evidence is corrupt.
    fn outbound_discord_target(
        &self,
        session_id: SessionId,
        topic: &str,
    ) -> Result<Option<OutboundDiscordTarget>, DiscordChannelStoreError>;
}

/// Validates one canonical Discord snowflake represented without integer narrowing.
#[must_use]
pub fn validate_discord_snowflake(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && !value.starts_with('0')
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u64>().is_ok_and(|value| value != 0)
}

/// Validates all non-secret Discord binding fields and credential evidence.
///
/// # Errors
///
/// Returns [`DiscordChannelStoreError::InvalidContract`] for malformed identity or evidence.
pub fn validate_discord_binding(
    discord_user_id: &str,
    discord_channel_id: &str,
    bot_user_id: &str,
    bot_username: &str,
    token_secret_id: &str,
    token_digest: &str,
) -> Result<(), DiscordChannelStoreError> {
    let username_valid = !bot_username.is_empty()
        && bot_username.len() <= DISCORD_MAXIMUM_BOT_USERNAME_BYTES
        && bot_username.trim() == bot_username
        && !bot_username.chars().any(char::is_control);
    if !validate_discord_snowflake(discord_user_id)
        || !validate_discord_snowflake(discord_channel_id)
        || !validate_discord_snowflake(bot_user_id)
        || discord_user_id == bot_user_id
        || !username_valid
        || !valid_provider_secret_id(token_secret_id)
        || !is_sha256_digest(token_digest)
    {
        Err(DiscordChannelStoreError::InvalidContract(
            "Discord identity or credential evidence is invalid".to_owned(),
        ))
    } else {
        Ok(())
    }
}

/// Stable session idempotency key for one Discord message.
///
/// # Errors
///
/// Returns [`DiscordChannelStoreError::InvalidContract`] for a noncanonical snowflake.
pub fn discord_input_dedupe_key(
    binding_id: ChannelBindingId,
    message_id: &str,
) -> Result<String, DiscordChannelStoreError> {
    if validate_discord_snowflake(message_id) {
        Ok(format!("discord:{binding_id}:{message_id}"))
    } else {
        Err(DiscordChannelStoreError::InvalidContract(
            "Discord message identity is invalid".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{discord_input_dedupe_key, validate_discord_binding, validate_discord_snowflake};
    use mealy_domain::ChannelBindingId;

    #[test]
    fn snowflakes_are_canonical_unsigned_decimal_values() {
        assert!(validate_discord_snowflake("1234567890123456789"));
        assert!(validate_discord_snowflake("18446744073709551615"));
        for invalid in ["", "0", "01", "-1", "+1", "1.0", "18446744073709551616"] {
            assert!(!validate_discord_snowflake(invalid), "accepted {invalid:?}");
        }
    }

    #[test]
    fn binding_and_dedupe_contracts_reject_ambiguous_identity() {
        let binding_id = ChannelBindingId::new();
        assert_eq!(
            discord_input_dedupe_key(binding_id, "42").expect("dedupe"),
            format!("discord:{binding_id}:42")
        );
        assert!(
            validate_discord_binding(
                "42",
                "43",
                "44",
                "mealy_bot",
                "discord.binding",
                &"a".repeat(64),
            )
            .is_ok()
        );
        assert!(
            validate_discord_binding(
                "42",
                "43",
                "42",
                "mealy_bot",
                "discord.binding",
                &"a".repeat(64),
            )
            .is_err()
        );
    }
}
