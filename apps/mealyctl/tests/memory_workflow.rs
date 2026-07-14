//! Process-boundary proof for the owner-friendly governed-memory workflow.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mealy_application::sha256_digest;
use mealy_protocol::{API_VERSION, LocalConnectionInfo};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    process::Command,
    sync::mpsc,
    thread,
    time::Duration,
};

#[test]
fn remember_proposes_exact_provenance_then_owner_authorizes_activation() {
    let home = private_temporary_home();
    let content = "The owner prefers concise operational summaries";
    let content_digest = sha256_digest(content.as_bytes());
    let proposed = memory_response("proposed", 0, content, &content_digest);
    let active = memory_response("active", 1, content, &content_digest);
    let (base_url, requests, server) = serve_memory_responses(vec![
        ("200 OK", proposed.to_string()),
        ("200 OK", active.to_string()),
    ]);
    write_connection(home.path(), &base_url);

    let output = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home.path())
        .args([
            "memory",
            "remember",
            "--workspace",
            "mealy://assistant/no-workspace",
            content,
            "--approve",
        ])
        .output()
        .expect("run direct memory workflow");
    assert!(
        output.status.success(),
        "memory workflow failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).expect("active memory response");
    assert_eq!(response["memoryId"], "memory-1");
    assert_eq!(response["status"], "active");

    let proposal = requests.recv().expect("captured proposal");
    assert_eq!(proposal.method_and_target, "POST /v1/memories");
    assert_eq!(
        proposal.body["workspaceIdentity"],
        "mealy://assistant/no-workspace"
    );
    assert_eq!(proposal.body["content"], content);
    assert_eq!(proposal.body["category"], "fact");
    assert_eq!(proposal.body["sensitivity"], "private");
    assert_eq!(proposal.body["retention"], "standard");
    assert_eq!(proposal.body["sources"][0]["digest"], content_digest);
    assert_eq!(
        proposal.body["sources"][0]["locator"],
        format!("owner://mealyctl/direct/{content_digest}")
    );
    assert_bearer(&proposal.headers);

    let activation = requests.recv().expect("captured activation");
    assert_eq!(
        activation.method_and_target,
        "POST /v1/memories/memory-1/activate"
    );
    assert_eq!(activation.body["revisionId"], "revision-1");
    assert_eq!(activation.body["authorization"], "owner_approval");
    assert_bearer(&activation.headers);
    server.join().expect("memory server");

    let unapproved = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home.path())
        .args([
            "memory",
            "remember",
            "--workspace",
            "mealy://assistant/no-workspace",
            "must not be proposed",
        ])
        .output()
        .expect("run unapproved memory workflow");
    assert!(!unapproved.status.success());
    assert!(String::from_utf8_lossy(&unapproved.stderr).contains("requires --approve"));
}

#[test]
fn activation_failure_reports_the_durable_proposal_for_recovery() {
    let home = private_temporary_home();
    let content = "A recoverable proposed memory";
    let digest = sha256_digest(content.as_bytes());
    let proposed = memory_response("proposed", 0, content, &digest);
    let conflict = json!({
        "apiVersion": API_VERSION,
        "code": "conflict",
        "message": "activation conflict",
        "retryable": false
    });
    let (base_url, _requests, server) = serve_memory_responses(vec![
        ("200 OK", proposed.to_string()),
        ("409 Conflict", conflict.to_string()),
    ]);
    write_connection(home.path(), &base_url);
    let output = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home.path())
        .args([
            "memory",
            "remember",
            "--workspace",
            "mealy://assistant/no-workspace",
            content,
            "--approve",
        ])
        .output()
        .expect("run failed memory activation");
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("memory-1"));
    assert!(error.contains("revision-1"));
    assert!(error.contains("proposed but not activated"));
    server.join().expect("memory server");
}

#[derive(Debug)]
struct CapturedRequest {
    method_and_target: String,
    headers: String,
    body: Value,
}

fn private_temporary_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700))
            .expect("private temporary Mealy home");
    }
    home
}

fn serve_memory_responses(
    responses: Vec<(&str, String)>,
) -> (
    String,
    mpsc::Receiver<CapturedRequest>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind memory server");
    let address = listener.local_addr().expect("memory server address");
    let (sender, receiver) = mpsc::channel();
    let responses = responses
        .into_iter()
        .map(|(status, body)| (status.to_owned(), body))
        .collect::<Vec<_>>();
    let handle = thread::spawn(move || {
        for (status, response_body) in responses {
            let (mut stream, _) = listener.accept().expect("accept memory request");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("memory request timeout");
            let (headers, body) = read_json_request(&mut stream);
            let method_and_target = headers
                .lines()
                .next()
                .and_then(|line| line.strip_suffix(" HTTP/1.1"))
                .expect("request line")
                .to_owned();
            sender
                .send(CapturedRequest {
                    method_and_target,
                    headers,
                    body,
                })
                .expect("capture memory request");
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                response_body.len()
            )
            .expect("write memory response");
        }
    });
    (format!("http://{address}"), receiver, handle)
}

fn read_json_request(stream: &mut impl Read) -> (String, Value) {
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk).expect("read memory request");
        assert!(read != 0, "memory request ended before headers");
        raw.extend_from_slice(&chunk[..read]);
        if let Some(index) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = String::from_utf8(raw[..header_end].to_vec()).expect("memory headers");
    let length = headers
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("content length"))
            })
        })
        .expect("request content length");
    while raw.len().saturating_sub(header_end) < length {
        let read = stream.read(&mut chunk).expect("read memory request body");
        assert!(read != 0, "memory request body ended early");
        raw.extend_from_slice(&chunk[..read]);
    }
    let body =
        serde_json::from_slice(&raw[header_end..header_end + length]).expect("memory request JSON");
    (headers, body)
}

fn write_connection(home: &Path, base_url: &str) {
    let descriptor = LocalConnectionInfo {
        api_version: API_VERSION.to_owned(),
        base_url: base_url.to_owned(),
        bearer_token: URL_SAFE_NO_PAD.encode([7_u8; 32]),
        principal_id: "principal-1".to_owned(),
        channel_binding_id: "binding-1".to_owned(),
    };
    let path = home.join("connection.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&descriptor).expect("connection descriptor"),
    )
    .expect("write connection descriptor");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("private connection permissions");
    }
}

fn memory_response(status: &str, revision: u64, content: &str, digest: &str) -> Value {
    json!({
        "apiVersion": API_VERSION,
        "memoryId": "memory-1",
        "principalId": "principal-1",
        "workspaceIdentity": "mealy://assistant/no-workspace",
        "status": status,
        "revision": revision,
        "category": "fact",
        "confidenceBasisPoints": 8000,
        "sensitivity": "private",
        "retention": "standard",
        "createdAtMs": 1,
        "lastVerifiedAtMs": 1,
        "revisions": [{
            "revisionId": "revision-1",
            "ordinal": 1,
            "status": status,
            "content": content,
            "contentDigest": digest,
            "confidenceBasisPoints": 8000,
            "sensitivity": "private",
            "retention": "standard",
            "supersedesRevisionId": null,
            "sources": [{
                "locator": format!("owner://mealyctl/direct/{digest}"),
                "digest": digest
            }],
            "createdAtMs": 1,
            "lastVerifiedAtMs": 1
        }]
    })
}

fn assert_bearer(headers: &str) {
    let expected = format!("Bearer {}", URL_SAFE_NO_PAD.encode([7_u8; 32]));
    assert!(headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("authorization") && value.trim() == expected
        })
    }));
}
