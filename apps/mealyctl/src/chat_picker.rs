//! Bounded terminal-only recent-conversation selection.

use super::{CliError, authorized, decode, terminal_safe_single_line, unsafe_terminal_character};
use mealy_protocol::{API_VERSION, LocalConnectionInfo, SessionSummaryResponse, SessionsResponse};
use reqwest::Client;
use std::{
    io::{BufRead, IsTerminal as _, Read as _, Write},
    time::{SystemTime, UNIX_EPOCH},
};

const MAXIMUM_INPUT_BYTES: usize = 64;
const MAXIMUM_SESSION_ID_BYTES: usize = 128;
const MAXIMUM_STATUS_BYTES: usize = 64;
const MAXIMUM_SESSIONS: usize = 20;

pub(super) async fn pick_recent_chat_session(
    client: &Client,
    connection: &LocalConnectionInfo,
) -> Result<Option<String>, CliError> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    if !stdin.is_terminal() || !stdout.is_terminal() || !stderr.is_terminal() {
        return Err(CliError::ChatPickerRequiresTerminal);
    }
    let response = authorized(
        client.get(format!(
            "{}/v1/sessions?limit={MAXIMUM_SESSIONS}",
            connection.base_url
        )),
        connection,
    )
    .send()
    .await?;
    let sessions = decode::<SessionsResponse>(response).await?;
    validate_picker_response(&sessions)?;
    if sessions.sessions.is_empty() {
        return Err(CliError::NoRecentSession);
    }
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliError::Protocol("system time predates the Unix epoch".to_owned()))?
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX);
    let mut input = stdin.lock();
    let mut prompt = stderr.lock();
    render_recent_chat_sessions(&sessions.sessions, now_ms, &mut prompt)?;
    for _ in 0..3 {
        write!(
            prompt,
            "Choose a conversation [1-{}], or q to cancel: ",
            sessions.sessions.len()
        )?;
        prompt.flush()?;
        let mut line = String::new();
        let mut bounded = (&mut input).take((MAXIMUM_INPUT_BYTES + 1) as u64);
        let bytes = bounded.read_line(&mut line)?;
        let value = line.trim();
        if bytes == 0 {
            return Ok(None);
        }
        if bytes <= MAXIMUM_INPUT_BYTES
            && value.len() <= 16
            && matches!(value.to_ascii_lowercase().as_str(), "q" | "quit")
        {
            return Ok(None);
        }
        if bytes <= MAXIMUM_INPUT_BYTES
            && value.len() <= 16
            && !value.chars().any(char::is_control)
            && let Ok(index) = value.parse::<usize>()
            && let Some(session) = index
                .checked_sub(1)
                .and_then(|index| sessions.sessions.get(index))
        {
            return Ok(Some(session.session_id.clone()));
        }
        writeln!(
            prompt,
            "Enter a number from 1 to {}, or q.",
            sessions.sessions.len()
        )?;
    }
    Err(CliError::InvalidChatSelection)
}

fn validate_picker_response(response: &SessionsResponse) -> Result<(), CliError> {
    if response.api_version != API_VERSION {
        return Err(CliError::Protocol(
            "recent-session picker received an unsupported API version".to_owned(),
        ));
    }
    if response.sessions.len() > MAXIMUM_SESSIONS {
        return Err(CliError::Protocol(format!(
            "recent-session picker exceeded its {MAXIMUM_SESSIONS}-session response bound"
        )));
    }
    if response
        .sessions
        .iter()
        .any(|session| !valid_summary(session))
        || response
            .sessions
            .windows(2)
            .any(|pair| pair[0].updated_at_ms < pair[1].updated_at_ms)
    {
        return Err(CliError::Protocol(
            "recent-session picker received invalid or unordered session summaries".to_owned(),
        ));
    }
    Ok(())
}

fn valid_summary(session: &SessionSummaryResponse) -> bool {
    !session.session_id.is_empty()
        && session.session_id.len() <= MAXIMUM_SESSION_ID_BYTES
        && !session.session_id.chars().any(unsafe_terminal_character)
        && !session.status.is_empty()
        && session.status.len() <= MAXIMUM_STATUS_BYTES
        && !session.status.chars().any(unsafe_terminal_character)
        && session.created_at_ms >= 0
        && session.updated_at_ms >= session.created_at_ms
        && session.active_turn_id.as_ref().is_none_or(|turn_id| {
            !turn_id.is_empty()
                && turn_id.len() <= MAXIMUM_SESSION_ID_BYTES
                && !turn_id.chars().any(unsafe_terminal_character)
        })
}

fn render_recent_chat_sessions(
    sessions: &[SessionSummaryResponse],
    now_ms: i64,
    prompt: &mut impl Write,
) -> Result<(), CliError> {
    writeln!(prompt, "Recent Mealy conversations (newest first):")?;
    for (index, session) in sessions.iter().enumerate() {
        let activity = if session.active_turn_id.is_some() {
            "active turn".to_owned()
        } else if session.pending_inputs == 1 {
            "1 queued input".to_owned()
        } else if session.pending_inputs > 1 {
            format!("{} queued inputs", session.pending_inputs)
        } else {
            "idle".to_owned()
        };
        writeln!(
            prompt,
            "  {}. {} | {} | {} | {}",
            index + 1,
            terminal_safe_single_line(&session.session_id),
            terminal_safe_single_line(&session.status),
            relative_age(session.updated_at_ms, now_ms),
            activity
        )?;
    }
    Ok(())
}

fn relative_age(updated_at_ms: i64, now_ms: i64) -> String {
    let age_seconds = now_ms.saturating_sub(updated_at_ms).max(0) / 1_000;
    if age_seconds < 60 {
        "updated just now".to_owned()
    } else if age_seconds < 3_600 {
        format!("updated {}m ago", age_seconds / 60)
    } else if age_seconds < 86_400 {
        format!("updated {}h ago", age_seconds / 3_600)
    } else {
        format!("updated {}d ago", age_seconds / 86_400)
    }
}

#[cfg(test)]
mod tests {
    use super::{relative_age, valid_summary, validate_picker_response};
    use mealy_protocol::{API_VERSION, SessionSummaryResponse, SessionsResponse};

    fn summary(session_id: &str, updated_at_ms: i64) -> SessionSummaryResponse {
        SessionSummaryResponse {
            session_id: session_id.to_owned(),
            status: "idle".to_owned(),
            revision: 2,
            pending_inputs: 0,
            active_turn_id: None,
            created_at_ms: 1_800_000_000_000,
            updated_at_ms,
        }
    }

    #[test]
    fn recency_is_concise_and_never_future_negative() {
        let now = 1_800_000_000_000_i64;
        assert_eq!(relative_age(now, now), "updated just now");
        assert_eq!(relative_age(now + 60_000, now), "updated just now");
        assert_eq!(relative_age(now - 5 * 60_000, now), "updated 5m ago");
        assert_eq!(relative_age(now - 3 * 3_600_000, now), "updated 3h ago");
        assert_eq!(relative_age(now - 2 * 86_400_000, now), "updated 2d ago");
    }

    #[test]
    fn summaries_are_bounded_ordered_and_terminal_safe() {
        let mut value = summary("019f0000-0000-7000-8000-000000000001", 1_800_000_001_000);
        assert!(valid_summary(&value));
        value.status = "idle\u{001b}[31m".to_owned();
        assert!(!valid_summary(&value));
        value.status = "idle".to_owned();
        value.session_id = "s".repeat(129);
        assert!(!valid_summary(&value));
        value.session_id = "session".to_owned();
        value.updated_at_ms = value.created_at_ms - 1;
        assert!(!valid_summary(&value));

        let ordered = SessionsResponse {
            api_version: API_VERSION.to_owned(),
            sessions: vec![
                summary("newer", 1_800_000_002_000),
                summary("older", 1_800_000_001_000),
            ],
        };
        assert!(validate_picker_response(&ordered).is_ok());
        let mut unordered = ordered;
        unordered.sessions.reverse();
        assert!(validate_picker_response(&unordered).is_err());
    }
}
