use crate::{TaskId, ValidationId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Canonical task lifecycle state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    /// Accepted but not currently leased.
    Queued,
    /// Actively executing under a valid lease.
    Running,
    /// Durably parked for approval, user input, a child, or retry time.
    Waiting,
    /// Explicitly paused by an authorized principal.
    Paused,
    /// Cancellation was requested and workers are draining.
    Cancelling,
    /// Completed with required evidence.
    Succeeded,
    /// Reached a terminal failure.
    Failed,
    /// Terminated by cancellation.
    Cancelled,
}

impl TaskStatus {
    /// Returns whether no later task transition is permitted.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}

/// Canonical state of a task aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskState {
    id: TaskId,
    status: TaskStatus,
    revision: u64,
    validation_required: bool,
    validation_id: Option<ValidationId>,
}

impl TaskState {
    /// Creates a newly queued task at revision zero.
    #[must_use]
    pub const fn new(id: TaskId, validation_required: bool) -> Self {
        Self {
            id,
            status: TaskStatus::Queued,
            revision: 0,
            validation_required,
            validation_id: None,
        }
    }

    /// Returns the stable task ID.
    #[must_use]
    pub const fn id(&self) -> TaskId {
        self.id
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn status(&self) -> TaskStatus {
        self.status
    }

    /// Returns the optimistic-concurrency revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns whether successful completion requires validation evidence.
    #[must_use]
    pub const fn validation_required(&self) -> bool {
        self.validation_required
    }

    /// Returns the validation record attached to successful completion.
    #[must_use]
    pub const fn validation_id(&self) -> Option<ValidationId> {
        self.validation_id
    }

    /// Moves queued work into active execution.
    ///
    /// # Errors
    ///
    /// Returns [`TaskError`] when the transition is invalid or the revision overflows.
    pub fn start(&mut self) -> Result<TaskTransition, TaskError> {
        self.transition(TaskStatus::Running)
    }

    /// Parks active work at a durable wait boundary.
    ///
    /// # Errors
    ///
    /// Returns [`TaskError`] when the transition is invalid or the revision overflows.
    pub fn wait(&mut self) -> Result<TaskTransition, TaskError> {
        self.transition(TaskStatus::Waiting)
    }

    /// Returns waiting or paused work to the runnable queue.
    ///
    /// # Errors
    ///
    /// Returns [`TaskError`] when the transition is invalid or the revision overflows.
    pub fn resume(&mut self) -> Result<TaskTransition, TaskError> {
        self.transition(TaskStatus::Queued)
    }

    /// Pauses active work by owner request.
    ///
    /// # Errors
    ///
    /// Returns [`TaskError`] when the transition is invalid or the revision overflows.
    pub fn pause(&mut self) -> Result<TaskTransition, TaskError> {
        self.transition(TaskStatus::Paused)
    }

    /// Begins bounded cancellation of active work.
    ///
    /// # Errors
    ///
    /// Returns [`TaskError`] when the transition is invalid or the revision overflows.
    pub fn request_cancel(&mut self) -> Result<TaskTransition, TaskError> {
        self.transition(TaskStatus::Cancelling)
    }

    /// Records that cancellation draining has finished.
    ///
    /// # Errors
    ///
    /// Returns [`TaskError`] when the transition is invalid or the revision overflows.
    pub fn finish_cancel(&mut self) -> Result<TaskTransition, TaskError> {
        self.transition(TaskStatus::Cancelled)
    }

    /// Completes active work as failed.
    ///
    /// # Errors
    ///
    /// Returns [`TaskError`] when the transition is invalid or the revision overflows.
    pub fn fail(&mut self) -> Result<TaskTransition, TaskError> {
        self.transition(TaskStatus::Failed)
    }

    /// Completes active work successfully after enforcing its validation gate.
    ///
    /// # Errors
    ///
    /// Returns [`TaskError`] if evidence is required but absent, the transition is invalid, or
    /// the revision overflows.
    pub fn succeed(
        &mut self,
        validation_id: Option<ValidationId>,
    ) -> Result<TaskTransition, TaskError> {
        if self.validation_required && validation_id.is_none() {
            return Err(TaskError::ValidationRequired { task_id: self.id });
        }
        let transition = self.transition(TaskStatus::Succeeded)?;
        self.validation_id = validation_id;
        Ok(transition)
    }

    fn transition(&mut self, target: TaskStatus) -> Result<TaskTransition, TaskError> {
        if !allowed(self.status, target) {
            return Err(TaskError::InvalidTransition {
                task_id: self.id,
                from: self.status,
                to: target,
            });
        }

        let transition = TaskTransition {
            task_id: self.id,
            from: self.status,
            to: target,
            previous_revision: self.revision,
            new_revision: self
                .revision
                .checked_add(1)
                .ok_or(TaskError::RevisionOverflow { task_id: self.id })?,
        };
        self.status = target;
        self.revision = transition.new_revision;
        Ok(transition)
    }
}

const fn allowed(from: TaskStatus, to: TaskStatus) -> bool {
    matches!(
        (from, to),
        (
            TaskStatus::Queued,
            TaskStatus::Running | TaskStatus::Cancelled
        ) | (
            TaskStatus::Running,
            TaskStatus::Waiting
                | TaskStatus::Paused
                | TaskStatus::Cancelling
                | TaskStatus::Succeeded
                | TaskStatus::Failed
        ) | (
            TaskStatus::Waiting | TaskStatus::Paused,
            TaskStatus::Queued | TaskStatus::Cancelled
        ) | (
            TaskStatus::Cancelling,
            TaskStatus::Cancelled | TaskStatus::Failed
        )
    )
}

/// Immutable fact describing one accepted task transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskTransition {
    /// Task aggregate that changed.
    task_id: TaskId,
    /// State before the transition.
    from: TaskStatus,
    /// State after the transition.
    to: TaskStatus,
    /// Revision checked by the caller.
    previous_revision: u64,
    /// Revision to persist atomically with the event.
    new_revision: u64,
}

impl TaskTransition {
    /// Returns the task aggregate that changed.
    #[must_use]
    pub const fn task_id(self) -> TaskId {
        self.task_id
    }

    /// Returns the state before the transition.
    #[must_use]
    pub const fn from(self) -> TaskStatus {
        self.from
    }

    /// Returns the state after the transition.
    #[must_use]
    pub const fn to(self) -> TaskStatus {
        self.to
    }

    /// Returns the revision that must still be current when the transition is committed.
    #[must_use]
    pub const fn previous_revision(self) -> u64 {
        self.previous_revision
    }

    /// Returns the new revision produced by the accepted transition.
    #[must_use]
    pub const fn new_revision(self) -> u64 {
        self.new_revision
    }
}

/// A rejected task transition.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TaskError {
    /// The requested lifecycle edge is not permitted.
    #[error("task {task_id} cannot transition from {from:?} to {to:?}")]
    InvalidTransition {
        /// Task being changed.
        task_id: TaskId,
        /// Current state.
        from: TaskStatus,
        /// Requested state.
        to: TaskStatus,
    },
    /// Successful completion requires a validation record.
    #[error("task {task_id} requires validation before success")]
    ValidationRequired {
        /// Task missing validation.
        task_id: TaskId,
    },
    /// The optimistic-concurrency revision exhausted its integer range.
    #[error("task {task_id} revision overflow")]
    RevisionOverflow {
        /// Task whose revision overflowed.
        task_id: TaskId,
    },
}

#[cfg(test)]
mod tests {
    use super::{TaskError, TaskState, TaskStatus};
    use crate::{TaskId, ValidationId};

    #[test]
    fn valid_lifecycle_increments_revision() {
        let mut task = TaskState::new(TaskId::new(), false);
        let started = task.start().expect("start queued task");
        assert_eq!(started.previous_revision(), 0);
        assert_eq!(started.new_revision(), 1);
        task.wait().expect("park running task");
        task.resume().expect("queue waiting task");
        task.start().expect("restart queued task");
        task.succeed(None)
            .expect("complete unvalidated low-risk task");
        assert_eq!(task.status(), TaskStatus::Succeeded);
        assert_eq!(task.revision(), 5);
    }

    #[test]
    fn validation_gate_prevents_false_success() {
        let mut task = TaskState::new(TaskId::new(), true);
        task.start().expect("start queued task");
        assert!(matches!(
            task.succeed(None),
            Err(TaskError::ValidationRequired { .. })
        ));
        let validation_id = ValidationId::new();
        task.succeed(Some(validation_id))
            .expect("complete validated task");
        assert_eq!(task.validation_id(), Some(validation_id));
    }

    #[test]
    fn terminal_state_cannot_be_resumed() {
        let mut task = TaskState::new(TaskId::new(), false);
        task.start().expect("start queued task");
        task.fail().expect("fail running task");
        assert!(task.status().is_terminal());
        assert!(matches!(
            task.resume(),
            Err(TaskError::InvalidTransition {
                from: TaskStatus::Failed,
                ..
            })
        ));
    }
}
