use async_trait::async_trait;
use mealy_core::{MealyError, Result, TaskId};
use mealy_events::EventEnvelope;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Default)]
pub struct EventFilter {
    pub task_id: Option<TaskId>,
}

#[async_trait]
pub trait EventStore: Send + Sync {
    async fn append(&self, event: EventEnvelope) -> Result<()>;
    async fn list(&self, filter: EventFilter) -> Result<Vec<EventEnvelope>>;
}

#[derive(Clone, Default)]
pub struct InMemoryEventStore {
    events: Arc<Mutex<Vec<EventEnvelope>>>,
}

#[async_trait]
impl EventStore for InMemoryEventStore {
    async fn append(&self, event: EventEnvelope) -> Result<()> {
        let mut events = self
            .events
            .lock()
            .map_err(|_| MealyError::Storage("event store lock poisoned".into()))?;
        events.push(event);
        Ok(())
    }

    async fn list(&self, filter: EventFilter) -> Result<Vec<EventEnvelope>> {
        let events = self
            .events
            .lock()
            .map_err(|_| MealyError::Storage("event store lock poisoned".into()))?;

        Ok(events
            .iter()
            .filter(|event| {
                filter
                    .task_id
                    .is_none_or(|task_id| event.task_id == Some(task_id))
            })
            .cloned()
            .collect())
    }
}
