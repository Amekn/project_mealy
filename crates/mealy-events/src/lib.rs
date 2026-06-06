use mealy_core::{
    AgentId, AgentRunId, ChannelId, EventId, PrincipalId, SessionId, TaskId, Timestamp, WorkflowId,
    now,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EventType(String);

impl EventType {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for EventType {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for EventType {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EventVisibility {
    Internal,
    Timeline,
    Audit,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Sensitivity {
    Public,
    Internal,
    Private,
    Secret,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event_id: EventId,
    pub schema_version: u32,
    pub event_type: EventType,
    pub occurred_at: Timestamp,
    pub recorded_at: Timestamp,
    pub principal_id: Option<PrincipalId>,
    pub agent_id: Option<AgentId>,
    pub channel_id: Option<ChannelId>,
    pub session_id: Option<SessionId>,
    pub task_id: Option<TaskId>,
    pub workflow_id: Option<WorkflowId>,
    pub agent_run_id: Option<AgentRunId>,
    pub causation_id: Option<EventId>,
    pub correlation_id: Option<EventId>,
    pub idempotency_key: Option<String>,
    pub visibility: EventVisibility,
    pub sensitivity: Sensitivity,
    pub body: serde_json::Value,
}

impl EventEnvelope {
    pub fn new(event_type: impl Into<EventType>, body: serde_json::Value) -> Self {
        let timestamp = now();

        Self {
            event_id: EventId::new(),
            schema_version: 1,
            event_type: event_type.into(),
            occurred_at: timestamp,
            recorded_at: timestamp,
            principal_id: None,
            agent_id: None,
            channel_id: None,
            session_id: None,
            task_id: None,
            workflow_id: None,
            agent_run_id: None,
            causation_id: None,
            correlation_id: None,
            idempotency_key: None,
            visibility: EventVisibility::Internal,
            sensitivity: Sensitivity::Internal,
            body,
        }
    }

    pub fn with_task_id(mut self, task_id: TaskId) -> Self {
        self.task_id = Some(task_id);
        self
    }

    pub fn visible_on_timeline(mut self) -> Self {
        self.visibility = EventVisibility::Timeline;
        self
    }
}
