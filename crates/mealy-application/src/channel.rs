use crate::{InputAdmissionReceipt, OwnershipContext, is_sha256_digest, sha256_digest};
use hmac::{Hmac, KeyInit, Mac};
use mealy_domain::{ChannelBindingId, CorrelationId, EventId, PrincipalId, SessionId};
use sha2::Sha256;
use std::time::{Duration, SystemTime};
use thiserror::Error;

/// Versioned signature framing used by built-in signed webhook channels.
pub const WEBHOOK_SIGNATURE_VERSION: &str = "mealy.webhook.signature.v1";
/// Signature algorithm advertised to channel administrators.
pub const WEBHOOK_SIGNATURE_ALGORITHM: &str = "hmac-sha256";
/// Maximum accepted clock skew in either direction.
pub const WEBHOOK_MAXIMUM_CLOCK_SKEW: Duration = Duration::from_mins(5);
/// Exact signing-secret byte length.
pub const WEBHOOK_SIGNING_SECRET_BYTES: usize = 32;
/// Maximum external delivery identity bytes.
pub const WEBHOOK_MAXIMUM_DELIVERY_ID_BYTES: usize = 128;
/// Maximum one-use replay nonce bytes.
pub const WEBHOOK_MAXIMUM_NONCE_BYTES: usize = 128;

const MAXIMUM_EXTERNAL_SUBJECT_BYTES: usize = 1_024;
const MAXIMUM_CALLBACK_URL_BYTES: usize = 2_048;
const MAXIMUM_SIGNED_BODY_BYTES: usize = 1024 * 1024;

type HmacSha256 = Hmac<Sha256>;

/// Durable lifecycle of one verified external-subject binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebhookChannelStatus {
    /// Signature verification and outbound delivery are active.
    Active,
    /// All future inbound and outbound authority is terminally revoked.
    Revoked,
}

/// Owner-authorized projection of one signed webhook channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebhookChannelBindingView {
    /// Stable verified channel binding.
    pub binding_id: ChannelBindingId,
    /// Principal to which the external subject maps.
    pub principal_id: PrincipalId,
    /// Dedicated durable session owned by this binding.
    pub session_id: SessionId,
    /// Exact external identity claim expected in signed deliveries.
    pub external_subject: String,
    /// Owner-approved outbound webhook URL.
    pub callback_url: String,
    /// Digest of the brokered signing secret, never the secret itself.
    pub secret_digest: String,
    /// Current terminal lifecycle state.
    pub status: WebhookChannelStatus,
    /// Optimistic-concurrency revision.
    pub revision: u64,
    /// UTC creation time.
    pub created_at_ms: i64,
    /// UTC last-update time.
    pub updated_at_ms: i64,
}

/// Atomic creation of a verified binding and its dedicated session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterWebhookChannelCommit {
    /// Authenticated local administrator.
    pub administrative_ownership: OwnershipContext,
    /// New external binding identity.
    pub binding_id: ChannelBindingId,
    /// New dedicated session identity.
    pub session_id: SessionId,
    /// Exact external platform subject.
    pub external_subject: String,
    /// Approved delivery destination.
    pub callback_url: String,
    /// Digest of the secret already committed to owner-only broker storage.
    pub secret_digest: String,
    /// Canonical `session.created` event.
    pub session_event_id: EventId,
    /// Canonical `channel.webhook_registered` event.
    pub binding_event_id: EventId,
    /// End-to-end creation correlation.
    pub correlation_id: CorrelationId,
    /// Creation time.
    pub created_at: SystemTime,
}

/// Terminal revocation of a signed webhook binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevokeWebhookChannelCommit {
    /// Authenticated local administrator.
    pub administrative_ownership: OwnershipContext,
    /// Exact external binding.
    pub binding_id: ChannelBindingId,
    /// Optimistic-concurrency revision.
    pub expected_revision: u64,
    /// Canonical `channel.webhook_revoked` event.
    pub event_id: EventId,
    /// End-to-end revocation correlation.
    pub correlation_id: CorrelationId,
    /// Revocation time.
    pub revoked_at: SystemTime,
}

/// Durable replay reservation committed only after signature verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReserveWebhookDeliveryCommit {
    /// Exact verified binding.
    pub binding_id: ChannelBindingId,
    /// Stable platform delivery identity.
    pub delivery_id: String,
    /// One-use request nonce.
    pub nonce: String,
    /// Exact raw signed body digest.
    pub body_digest: String,
    /// Digest of the supplied signature evidence.
    pub signature_digest: String,
    /// Receipt time.
    pub received_at: SystemTime,
}

/// Outcome of reserving a signed platform delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebhookDeliveryReservation {
    /// This call durably consumed the nonce for this delivery.
    Reserved,
    /// The exact same delivery/body was already reserved or completed.
    Existing,
}

/// Attaches the canonical session admission receipt to its replay reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteWebhookDeliveryCommit {
    /// Exact verified binding.
    pub binding_id: ChannelBindingId,
    /// Stable platform delivery identity.
    pub delivery_id: String,
    /// Canonical idempotent session admission.
    pub admission: InputAdmissionReceipt,
    /// Completion time.
    pub completed_at: SystemTime,
}

/// Internal target for one existing session outbox delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundWebhookTarget {
    /// Verified binding owning the session.
    pub binding_id: ChannelBindingId,
    /// Owner-approved callback URL.
    pub callback_url: String,
    /// Digest required when resolving the brokered secret.
    pub secret_digest: String,
}

/// Channel binding, replay reservation, and outbound-routing persistence failures.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WebhookChannelStoreError {
    /// Binding is absent or hidden from the supplied owner.
    #[error("webhook channel was not found")]
    NotFound,
    /// Binding has been terminally revoked.
    #[error("webhook channel is revoked")]
    Revoked,
    /// A nonce was already consumed by a different delivery.
    #[error("webhook delivery replay was rejected")]
    Replay,
    /// Revision or immutable delivery evidence conflicts with canonical state.
    #[error("webhook channel operation conflicts with canonical state")]
    Conflict,
    /// A supplied binding, target, or receipt violates the store contract.
    #[error("webhook channel contract is invalid: {0}")]
    InvalidContract(String),
    /// Persistence is temporarily unavailable.
    #[error("webhook channel store is unavailable: {0}")]
    Unavailable(String),
    /// Stored canonical evidence violates an invariant.
    #[error("webhook channel invariant violation: {0}")]
    InvariantViolation(String),
}

/// Port for signed external channel administration, replay defense, and outbox routing.
pub trait WebhookChannelStore {
    /// Creates one external-subject binding and dedicated session atomically.
    ///
    /// # Errors
    ///
    /// Returns [`WebhookChannelStoreError`] for authorization, uniqueness, or persistence failure.
    fn register_webhook_channel(
        &mut self,
        commit: RegisterWebhookChannelCommit,
    ) -> Result<WebhookChannelBindingView, WebhookChannelStoreError>;

    /// Terminally revokes one owner-authorized binding.
    ///
    /// # Errors
    ///
    /// Returns [`WebhookChannelStoreError`] for ownership, revision, or lifecycle conflict.
    fn revoke_webhook_channel(
        &mut self,
        commit: RevokeWebhookChannelCommit,
    ) -> Result<WebhookChannelBindingView, WebhookChannelStoreError>;

    /// Loads one binding for signature verification, including revoked state.
    ///
    /// # Errors
    ///
    /// Returns [`WebhookChannelStoreError`] when absent or canonical evidence is invalid.
    fn webhook_channel_for_verification(
        &self,
        binding_id: ChannelBindingId,
    ) -> Result<WebhookChannelBindingView, WebhookChannelStoreError>;

    /// Loads one binding through authenticated owner administration.
    ///
    /// # Errors
    ///
    /// Returns [`WebhookChannelStoreError`] when absent, unauthorized, or invalid.
    fn webhook_channel(
        &self,
        ownership: OwnershipContext,
        binding_id: ChannelBindingId,
    ) -> Result<WebhookChannelBindingView, WebhookChannelStoreError>;

    /// Lists deterministic owner-authorized signed webhook bindings.
    ///
    /// # Errors
    ///
    /// Returns [`WebhookChannelStoreError`] for authorization or persistence failure.
    fn webhook_channels(
        &self,
        ownership: OwnershipContext,
    ) -> Result<Vec<WebhookChannelBindingView>, WebhookChannelStoreError>;

    /// Atomically consumes a nonce or recognizes the exact previously verified delivery.
    ///
    /// # Errors
    ///
    /// Returns [`WebhookChannelStoreError::Replay`] when another delivery consumed the nonce.
    fn reserve_webhook_delivery(
        &mut self,
        commit: ReserveWebhookDeliveryCommit,
    ) -> Result<WebhookDeliveryReservation, WebhookChannelStoreError>;

    /// Idempotently attaches a canonical session receipt to the replay reservation.
    ///
    /// # Errors
    ///
    /// Returns [`WebhookChannelStoreError`] when evidence conflicts or persistence fails.
    fn complete_webhook_delivery(
        &mut self,
        commit: CompleteWebhookDeliveryCommit,
    ) -> Result<(), WebhookChannelStoreError>;

    /// Resolves an active signed webhook destination for a supported session outbox topic.
    ///
    /// # Errors
    ///
    /// Returns [`WebhookChannelStoreError`] when stored routing evidence is invalid.
    fn outbound_webhook_target(
        &self,
        session_id: SessionId,
        topic: &str,
    ) -> Result<Option<OutboundWebhookTarget>, WebhookChannelStoreError>;
}

/// Signs exact raw webhook bytes under unambiguous versioned framing.
///
/// # Errors
///
/// Returns [`WebhookSignatureError`] for invalid secrets, fields, timestamps, or body bounds.
pub fn sign_webhook(
    secret: &[u8],
    binding_id: ChannelBindingId,
    timestamp_ms: i64,
    nonce: &str,
    body: &[u8],
) -> Result<String, WebhookSignatureError> {
    if secret.len() != WEBHOOK_SIGNING_SECRET_BYTES {
        return Err(WebhookSignatureError::InvalidSecret);
    }
    let material = webhook_signature_material(binding_id, timestamp_ms, nonce, body)?;
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|_| WebhookSignatureError::InvalidSecret)?;
    mac.update(&material);
    Ok(lowercase_hex(&mac.finalize().into_bytes()))
}

/// Verifies a lowercase HMAC signature in constant time after strict decoding.
///
/// # Errors
///
/// Returns [`WebhookSignatureError`] for malformed evidence or a signature mismatch.
pub fn verify_webhook_signature(
    secret: &[u8],
    binding_id: ChannelBindingId,
    timestamp_ms: i64,
    nonce: &str,
    body: &[u8],
    signature: &str,
) -> Result<(), WebhookSignatureError> {
    if secret.len() != WEBHOOK_SIGNING_SECRET_BYTES {
        return Err(WebhookSignatureError::InvalidSecret);
    }
    let material = webhook_signature_material(binding_id, timestamp_ms, nonce, body)?;
    let signature = decode_lowercase_hex(signature)?;
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|_| WebhookSignatureError::InvalidSecret)?;
    mac.update(&material);
    mac.verify_slice(&signature)
        .map_err(|_| WebhookSignatureError::Mismatch)
}

/// Validates a signed request timestamp against the bounded replay window.
///
/// # Errors
///
/// Returns [`WebhookSignatureError::StaleTimestamp`] outside the configured skew.
pub fn validate_webhook_timestamp(
    now: SystemTime,
    timestamp_ms: i64,
    maximum_skew: Duration,
) -> Result<(), WebhookSignatureError> {
    if maximum_skew.is_zero() || maximum_skew > Duration::from_hours(1) || timestamp_ms < 0 {
        return Err(WebhookSignatureError::InvalidTimestamp);
    }
    let now_ms = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| WebhookSignatureError::InvalidTimestamp)?
        .as_millis();
    let timestamp_ms =
        u128::try_from(timestamp_ms).map_err(|_| WebhookSignatureError::InvalidTimestamp)?;
    if now_ms.abs_diff(timestamp_ms) > maximum_skew.as_millis() {
        return Err(WebhookSignatureError::StaleTimestamp);
    }
    Ok(())
}

/// Validates owner-visible binding fields before secret or persistence mutation.
///
/// # Errors
///
/// Returns [`WebhookSignatureError::InvalidField`] for malformed bounded values.
pub fn validate_webhook_binding_fields(
    external_subject: &str,
    callback_url: &str,
    secret_digest: &str,
) -> Result<(), WebhookSignatureError> {
    if !valid_field(external_subject, MAXIMUM_EXTERNAL_SUBJECT_BYTES)
        || !valid_field(callback_url, MAXIMUM_CALLBACK_URL_BYTES)
        || !is_sha256_digest(secret_digest)
    {
        return Err(WebhookSignatureError::InvalidField);
    }
    Ok(())
}

/// Returns the stable session idempotency key for one verified platform delivery.
///
/// # Errors
///
/// Returns [`WebhookSignatureError::InvalidField`] for an invalid delivery identity.
pub fn webhook_input_dedupe_key(
    binding_id: ChannelBindingId,
    delivery_id: &str,
) -> Result<String, WebhookSignatureError> {
    if !valid_field(delivery_id, WEBHOOK_MAXIMUM_DELIVERY_ID_BYTES) {
        return Err(WebhookSignatureError::InvalidField);
    }
    Ok(format!("webhook:{binding_id}:{delivery_id}"))
}

/// Failure at the signed webhook authentication boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WebhookSignatureError {
    /// Secret is not exactly 32 random bytes.
    #[error("webhook signing secret is invalid")]
    InvalidSecret,
    /// Timestamp is negative or the configured window is invalid.
    #[error("webhook timestamp is invalid")]
    InvalidTimestamp,
    /// Timestamp lies outside the bounded replay window.
    #[error("webhook timestamp is outside the replay window")]
    StaleTimestamp,
    /// Nonce, delivery identity, subject, callback, signature, or body bound is invalid.
    #[error("webhook signature field is invalid")]
    InvalidField,
    /// HMAC does not authenticate the exact raw request.
    #[error("webhook signature does not match")]
    Mismatch,
}

fn webhook_signature_material(
    binding_id: ChannelBindingId,
    timestamp_ms: i64,
    nonce: &str,
    body: &[u8],
) -> Result<Vec<u8>, WebhookSignatureError> {
    if timestamp_ms < 0
        || !valid_field(nonce, WEBHOOK_MAXIMUM_NONCE_BYTES)
        || body.is_empty()
        || body.len() > MAXIMUM_SIGNED_BODY_BYTES
    {
        return Err(WebhookSignatureError::InvalidField);
    }
    let binding = binding_id.to_string();
    let timestamp = timestamp_ms.to_string();
    let mut material = Vec::with_capacity(
        WEBHOOK_SIGNATURE_VERSION.len()
            + binding.len()
            + timestamp.len()
            + nonce.len()
            + body.len()
            + 4,
    );
    for field in [
        WEBHOOK_SIGNATURE_VERSION.as_bytes(),
        binding.as_bytes(),
        timestamp.as_bytes(),
        nonce.as_bytes(),
    ] {
        material.extend_from_slice(field);
        material.push(0);
    }
    material.extend_from_slice(body);
    Ok(material)
}

fn valid_field(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(ALPHABET[usize::from(byte >> 4)]));
        encoded.push(char::from(ALPHABET[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_lowercase_hex(value: &str) -> Result<Vec<u8>, WebhookSignatureError> {
    if value.len() != 64 {
        return Err(WebhookSignatureError::InvalidField);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or(WebhookSignatureError::InvalidField)?;
            let low = hex_nibble(pair[1]).ok_or(WebhookSignatureError::InvalidField)?;
            Ok((high << 4) | low)
        })
        .collect()
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

/// Returns a safe digest of signature evidence for the replay audit row.
#[must_use]
pub fn webhook_signature_digest(signature: &str) -> String {
    sha256_digest(signature.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{
        WEBHOOK_MAXIMUM_CLOCK_SKEW, WebhookSignatureError, sign_webhook,
        validate_webhook_timestamp, verify_webhook_signature,
    };
    use mealy_domain::ChannelBindingId;
    use std::time::{Duration, SystemTime};

    #[test]
    fn signature_binds_raw_body_identity_timestamp_and_nonce() {
        let secret = [7_u8; 32];
        let binding = ChannelBindingId::new();
        let body = br#"{"content":"hello"}"#;
        let signature = sign_webhook(&secret, binding, 123, "nonce-1", body).expect("signature");
        verify_webhook_signature(&secret, binding, 123, "nonce-1", body, &signature)
            .expect("exact signature");
        assert_eq!(
            verify_webhook_signature(
                &secret,
                binding,
                123,
                "nonce-1",
                br#"{"content":"tampered"}"#,
                &signature,
            ),
            Err(WebhookSignatureError::Mismatch)
        );
        assert_eq!(
            verify_webhook_signature(&secret, binding, 123, "nonce-2", body, &signature),
            Err(WebhookSignatureError::Mismatch)
        );
    }

    #[test]
    fn timestamp_window_accepts_boundaries_and_rejects_replay_age() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        validate_webhook_timestamp(now, 700_000, WEBHOOK_MAXIMUM_CLOCK_SKEW)
            .expect("inclusive past boundary");
        validate_webhook_timestamp(now, 1_300_000, WEBHOOK_MAXIMUM_CLOCK_SKEW)
            .expect("inclusive future boundary");
        assert_eq!(
            validate_webhook_timestamp(now, 699_999, WEBHOOK_MAXIMUM_CLOCK_SKEW),
            Err(WebhookSignatureError::StaleTimestamp)
        );
    }
}
