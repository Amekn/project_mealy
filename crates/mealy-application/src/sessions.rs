use crate::{Clock, IdGenerator};
use mealy_domain::{
    ChannelBindingId, CorrelationId, DeliveryMode, EventId, InboxEntryId, OutboxId, PrincipalId,
    SessionId,
};
use std::time::SystemTime;
use thiserror::Error;

/// Authenticated identity attached to an application command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnershipContext {
    principal_id: PrincipalId,
    channel_binding_id: ChannelBindingId,
}

impl OwnershipContext {
    /// Creates an ownership context after the API adapter verifies both identities.
    #[must_use]
    pub const fn new(principal_id: PrincipalId, channel_binding_id: ChannelBindingId) -> Self {
        Self {
            principal_id,
            channel_binding_id,
        }
    }

    /// Returns the authenticated principal.
    #[must_use]
    pub const fn principal_id(self) -> PrincipalId {
        self.principal_id
    }

    /// Returns the verified channel binding.
    #[must_use]
    pub const fn channel_binding_id(self) -> ChannelBindingId {
        self.channel_binding_id
    }
}

/// Complete transaction input for creating a session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionCreationCommit {
    /// Stable session identifier.
    pub session_id: SessionId,
    /// Authenticated owner and channel binding.
    pub ownership: OwnershipContext,
    /// Immutable `session.created` journal-event identifier.
    pub event_id: EventId,
    /// Correlates the command and its journal fact.
    pub correlation_id: CorrelationId,
    /// Wall-clock instant assigned by the application layer.
    pub created_at: SystemTime,
}

/// Complete transaction input for admitting one session input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputAdmissionCommit {
    /// Session whose durable inbox receives the input.
    pub session_id: SessionId,
    /// Authenticated principal and channel binding.
    pub ownership: OwnershipContext,
    /// Stable identifier allocated for a newly accepted inbox entry.
    pub inbox_entry_id: InboxEntryId,
    /// Requested ordering behavior.
    pub delivery_mode: DeliveryMode,
    /// Stable channel-delivery deduplication key.
    pub dedupe_key: String,
    /// Bounded input content.
    pub content: String,
    /// Immutable `input.accepted` journal-event identifier.
    pub event_id: EventId,
    /// Durable acknowledgement-delivery identifier.
    pub outbox_id: OutboxId,
    /// Correlates the command, journal fact, and acknowledgement.
    pub correlation_id: CorrelationId,
    /// Wall-clock instant assigned by the application layer.
    pub accepted_at: SystemTime,
}

/// Durable receipt returned for an accepted or duplicate delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputAdmissionReceipt {
    /// Session that owns the input.
    pub session_id: SessionId,
    /// Stable inbox-entry identifier.
    pub inbox_entry_id: InboxEntryId,
    /// Positive monotonic sequence scoped to the session.
    pub inbox_sequence: u64,
    /// Ordering behavior bound to the idempotency key.
    pub delivery_mode: DeliveryMode,
    /// Journal event created by the original acceptance.
    pub event_id: EventId,
    /// Acknowledgement outbox record created by the original acceptance.
    pub outbox_id: OutboxId,
    /// Original correlation identifier.
    pub correlation_id: CorrelationId,
    /// Original acceptance time.
    pub accepted_at: SystemTime,
}

/// Result of idempotent input admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InputAdmissionOutcome {
    /// This command created the durable inbox entry.
    Accepted(InputAdmissionReceipt),
    /// The same delivery was already accepted; the original receipt is returned.
    Duplicate(InputAdmissionReceipt),
}

impl InputAdmissionOutcome {
    /// Returns the durable receipt regardless of whether this invocation created it.
    #[must_use]
    pub const fn receipt(&self) -> &InputAdmissionReceipt {
        match self {
            Self::Accepted(receipt) | Self::Duplicate(receipt) => receipt,
        }
    }

    /// Returns whether the store recognized an exact duplicate delivery.
    #[must_use]
    pub const fn is_duplicate(&self) -> bool {
        matches!(self, Self::Duplicate(_))
    }
}

/// Infrastructure failure visible to session use cases.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SessionStoreError {
    /// No authorized session exists for the supplied identifier.
    #[error("session was not found")]
    SessionNotFound,
    /// The authenticated principal or channel binding does not own the session.
    #[error("session access is unauthorized")]
    Unauthorized,
    /// The same idempotency key was reused with different immutable input.
    #[error("input idempotency key conflicts with the original delivery")]
    IdempotencyConflict,
    /// A concurrent revision or uniqueness check rejected the commit.
    #[error("session commit conflicted with concurrent state")]
    Conflict,
    /// The persistence dependency could not complete the operation.
    #[error("session store is unavailable: {0}")]
    Unavailable(String),
    /// Stored canonical data violates an application invariant.
    #[error("session store invariant violation: {0}")]
    InvariantViolation(String),
}

/// Port for atomic session and inbox transactions.
pub trait SessionStore {
    /// Creates the canonical session and its journal fact atomically.
    ///
    /// # Errors
    ///
    /// Returns [`SessionStoreError`] if authorization or persistence fails.
    fn create_session(&mut self, commit: SessionCreationCommit) -> Result<(), SessionStoreError>;

    /// Atomically authorizes, deduplicates, sequences, journals, and acknowledges an input.
    ///
    /// # Errors
    ///
    /// Returns [`SessionStoreError`] if authorization, idempotency, or persistence fails.
    fn admit_input(
        &mut self,
        commit: InputAdmissionCommit,
    ) -> Result<InputAdmissionOutcome, SessionStoreError>;
}

/// Byte limits enforced before input reaches persistence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputAdmissionLimits {
    maximum_dedupe_key_bytes: usize,
    maximum_content_bytes: usize,
}

impl InputAdmissionLimits {
    /// Creates explicit ingress byte limits.
    #[must_use]
    pub const fn new(maximum_dedupe_key_bytes: usize, maximum_content_bytes: usize) -> Self {
        Self {
            maximum_dedupe_key_bytes,
            maximum_content_bytes,
        }
    }

    /// Returns the maximum accepted UTF-8 byte length of a deduplication key.
    #[must_use]
    pub const fn maximum_dedupe_key_bytes(self) -> usize {
        self.maximum_dedupe_key_bytes
    }

    /// Returns the maximum accepted UTF-8 byte length of input content.
    #[must_use]
    pub const fn maximum_content_bytes(self) -> usize {
        self.maximum_content_bytes
    }
}

impl Default for InputAdmissionLimits {
    fn default() -> Self {
        Self::new(256, 1024 * 1024)
    }
}

/// Authenticated request to place content in a session's durable inbox.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmitInputCommand {
    /// Target session.
    pub session_id: SessionId,
    /// Verified caller identity.
    pub ownership: OwnershipContext,
    /// Stable source-delivery deduplication key.
    pub dedupe_key: String,
    /// Requested input ordering behavior.
    pub delivery_mode: DeliveryMode,
    /// User or channel input content.
    pub content: String,
}

/// Rejected application command.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SessionUseCaseError {
    /// A channel delivery must have a stable non-empty deduplication key.
    #[error("input deduplication key must not be empty")]
    EmptyDedupeKey,
    /// A byte boundary rejected an oversized deduplication key.
    #[error("input deduplication key is {actual} bytes; maximum is {maximum}")]
    DedupeKeyTooLarge {
        /// Actual encoded byte length.
        actual: usize,
        /// Configured maximum byte length.
        maximum: usize,
    },
    /// This initial text-input slice requires at least one UTF-8 byte of content.
    #[error("input content must not be empty")]
    EmptyContent,
    /// A byte boundary rejected oversized content.
    #[error("input content is {actual} bytes; maximum is {maximum}")]
    ContentTooLarge {
        /// Actual encoded byte length.
        actual: usize,
        /// Configured maximum byte length.
        maximum: usize,
    },
    /// Atomic persistence rejected the command.
    #[error(transparent)]
    Store(#[from] SessionStoreError),
}

/// Creates a session through the application transaction port.
///
/// # Errors
///
/// Returns [`SessionUseCaseError`] if the atomic store operation fails.
pub fn create_session(
    store: &mut impl SessionStore,
    clock: &impl Clock,
    ids: &impl IdGenerator,
    ownership: OwnershipContext,
) -> Result<SessionId, SessionUseCaseError> {
    let session_id = ids.generate_session_id();
    store.create_session(SessionCreationCommit {
        session_id,
        ownership,
        event_id: ids.generate_event_id(),
        correlation_id: ids.generate_correlation_id(),
        created_at: clock.now(),
    })?;
    Ok(session_id)
}

/// Durably admits one bounded, authenticated session input before acknowledgement.
///
/// # Errors
///
/// Returns [`SessionUseCaseError`] before persistence for invalid bounds, or after an atomic store
/// rejection for authorization, idempotency, conflict, or dependency failures.
pub fn admit_input(
    store: &mut impl SessionStore,
    clock: &impl Clock,
    ids: &impl IdGenerator,
    limits: InputAdmissionLimits,
    command: AdmitInputCommand,
) -> Result<InputAdmissionOutcome, SessionUseCaseError> {
    let dedupe_key_bytes = command.dedupe_key.len();
    if dedupe_key_bytes == 0 {
        return Err(SessionUseCaseError::EmptyDedupeKey);
    }
    if dedupe_key_bytes > limits.maximum_dedupe_key_bytes() {
        return Err(SessionUseCaseError::DedupeKeyTooLarge {
            actual: dedupe_key_bytes,
            maximum: limits.maximum_dedupe_key_bytes(),
        });
    }
    let content_bytes = command.content.len();
    if content_bytes == 0 {
        return Err(SessionUseCaseError::EmptyContent);
    }
    if content_bytes > limits.maximum_content_bytes() {
        return Err(SessionUseCaseError::ContentTooLarge {
            actual: content_bytes,
            maximum: limits.maximum_content_bytes(),
        });
    }

    store
        .admit_input(InputAdmissionCommit {
            session_id: command.session_id,
            ownership: command.ownership,
            inbox_entry_id: ids.generate_inbox_entry_id(),
            delivery_mode: command.delivery_mode,
            dedupe_key: command.dedupe_key,
            content: command.content,
            event_id: ids.generate_event_id(),
            outbox_id: ids.generate_outbox_id(),
            correlation_id: ids.generate_correlation_id(),
            accepted_at: clock.now(),
        })
        .map_err(SessionUseCaseError::from)
}

#[cfg(test)]
mod tests {
    use super::{
        AdmitInputCommand, InputAdmissionCommit, InputAdmissionLimits, InputAdmissionOutcome,
        InputAdmissionReceipt, OwnershipContext, SessionCreationCommit, SessionStore,
        SessionStoreError, SessionUseCaseError, admit_input, create_session,
    };
    use crate::{Clock, IdGenerator};
    use mealy_domain::{
        ChannelBindingId, CorrelationId, DeliveryMode, EventId, InboxEntryId, OutboxId,
        PrincipalId, SessionId,
    };
    use std::time::SystemTime;

    const NOW: SystemTime = SystemTime::UNIX_EPOCH;

    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            NOW
        }
    }

    struct FixedIds {
        session: SessionId,
        inbox_entry: InboxEntryId,
        event: EventId,
        outbox: OutboxId,
        correlation: CorrelationId,
    }

    impl FixedIds {
        fn new() -> Self {
            Self {
                session: SessionId::new(),
                inbox_entry: InboxEntryId::new(),
                event: EventId::new(),
                outbox: OutboxId::new(),
                correlation: CorrelationId::new(),
            }
        }
    }

    impl IdGenerator for FixedIds {
        fn generate_session_id(&self) -> SessionId {
            self.session
        }

        fn generate_inbox_entry_id(&self) -> InboxEntryId {
            self.inbox_entry
        }

        fn generate_event_id(&self) -> EventId {
            self.event
        }

        fn generate_outbox_id(&self) -> OutboxId {
            self.outbox
        }

        fn generate_correlation_id(&self) -> CorrelationId {
            self.correlation
        }
    }

    #[derive(Default)]
    struct RecordingStore {
        creation: Option<SessionCreationCommit>,
        admission: Option<InputAdmissionCommit>,
    }

    impl SessionStore for RecordingStore {
        fn create_session(
            &mut self,
            commit: SessionCreationCommit,
        ) -> Result<(), SessionStoreError> {
            self.creation = Some(commit);
            Ok(())
        }

        fn admit_input(
            &mut self,
            commit: InputAdmissionCommit,
        ) -> Result<InputAdmissionOutcome, SessionStoreError> {
            let receipt = InputAdmissionReceipt {
                session_id: commit.session_id,
                inbox_entry_id: commit.inbox_entry_id,
                inbox_sequence: 1,
                delivery_mode: commit.delivery_mode,
                event_id: commit.event_id,
                outbox_id: commit.outbox_id,
                correlation_id: commit.correlation_id,
                accepted_at: commit.accepted_at,
            };
            self.admission = Some(commit);
            Ok(InputAdmissionOutcome::Accepted(receipt))
        }
    }

    fn ownership() -> OwnershipContext {
        OwnershipContext::new(PrincipalId::new(), ChannelBindingId::new())
    }

    #[test]
    fn create_session_assigns_identity_and_time_before_store_commit() {
        let mut store = RecordingStore::default();
        let ids = FixedIds::new();
        let owner = ownership();
        let session_id = create_session(&mut store, &FixedClock, &ids, owner)
            .expect("create session through store port");

        assert_eq!(session_id, ids.session);
        let commit = store.creation.expect("creation commit captured");
        assert_eq!(commit.session_id, ids.session);
        assert_eq!(commit.ownership, owner);
        assert_eq!(commit.created_at, NOW);
    }

    #[test]
    fn admission_is_bounded_before_the_store_is_called() {
        let mut store = RecordingStore::default();
        let command = AdmitInputCommand {
            session_id: SessionId::new(),
            ownership: ownership(),
            dedupe_key: "delivery-1".to_owned(),
            delivery_mode: DeliveryMode::Queue,
            content: "too large".to_owned(),
        };
        let error = admit_input(
            &mut store,
            &FixedClock,
            &FixedIds::new(),
            InputAdmissionLimits::new(64, 3),
            command,
        )
        .expect_err("oversized content must fail");

        assert!(matches!(error, SessionUseCaseError::ContentTooLarge { .. }));
        assert!(store.admission.is_none());
    }

    #[test]
    fn accepted_admission_carries_the_exact_immutable_input() {
        let mut store = RecordingStore::default();
        let ids = FixedIds::new();
        let command = AdmitInputCommand {
            session_id: ids.session,
            ownership: ownership(),
            dedupe_key: "delivery-1".to_owned(),
            delivery_mode: DeliveryMode::SteerAtBoundary,
            content: "continue with this constraint".to_owned(),
        };
        let outcome = admit_input(
            &mut store,
            &FixedClock,
            &ids,
            InputAdmissionLimits::default(),
            command,
        )
        .expect("admit bounded input");

        assert!(!outcome.is_duplicate());
        assert_eq!(outcome.receipt().inbox_entry_id, ids.inbox_entry);
        let commit = store.admission.expect("admission commit captured");
        assert_eq!(commit.delivery_mode, DeliveryMode::SteerAtBoundary);
        assert_eq!(commit.accepted_at, NOW);
    }
}
