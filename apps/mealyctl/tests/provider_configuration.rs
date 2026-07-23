//! Process-boundary proof for offline provider configuration and credential brokering.

use mealy_application::sha256_digest;
use mealy_infrastructure::FileProviderSecretStore;
use serde_json::{Value, json};
use std::{
    fmt::Write as _,
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};

#[cfg(target_os = "linux")]
fn service_test_tempdir(prefix: &str) -> tempfile::TempDir {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("target/service-process-test-temp");
    fs::create_dir_all(&root).expect("service process test root");
    let root = root
        .canonicalize()
        .expect("canonical service process test root");
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(root)
        .expect("persistent service process test directory")
}

#[test]
#[allow(clippy::too_many_lines)]
fn provider_model_discovery_is_bounded_protocol_specific_and_read_only() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    let openai_body = json!({
        "object": "list",
        "data": [
            {"id": "gpt-new", "object": "model", "created": 30, "owned_by": "openai"},
            {"id": "embedding-only", "object": "model", "created": 20, "owned_by": "openai"},
            {"id": "gpt-old", "object": "model", "created": 10, "owned_by": "openai"}
        ]
    })
    .to_string();
    let (base_url, capture, server) = serve_model_list("200 OK", &openai_body);
    let output = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home.path())
        .args([
            "config",
            "provider-models",
            "--base-url",
            &base_url,
            "--credential-env",
            "MEALY_TEST_DISCOVERY_CREDENTIAL",
            "--contains",
            "GPT",
            "--limit",
            "1",
        ])
        .env("MEALY_TEST_DISCOVERY_CREDENTIAL", "openai-discovery-secret")
        .output()
        .expect("run OpenAI model discovery");
    assert!(
        output.status.success(),
        "OpenAI model discovery failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("openai-discovery-secret"));
    let response: Value = serde_json::from_slice(&output.stdout).expect("discovery response");
    assert_eq!(response["protocol"], "openai_responses");
    assert_eq!(response["returnedCount"], 1);
    assert_eq!(response["locallyTruncated"], true);
    assert_eq!(response["pricingIncluded"], false);
    assert_eq!(response["models"][0]["id"], "gpt-new");
    assert_eq!(response["models"][0]["contextTokens"], Value::Null);
    assert_eq!(response["models"][0]["tokenLimitsComplete"], false);
    let request = capture.recv().expect("captured OpenAI model request");
    assert!(request.starts_with("GET /v1/models HTTP/1.1\r\n"));
    assert!(request.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("authorization")
                && value.trim() == "Bearer openai-discovery-secret"
        })
    }));
    server.join().expect("OpenAI discovery server");

    let anthropic_body = json!({
        "data": [
            {
                "id": "claude-sonnet-test",
                "type": "model",
                "created_at": "2026-07-01T00:00:00Z",
                "display_name": "Claude Sonnet Test",
                "max_input_tokens": 200_000,
                "max_tokens": 64000,
                "capabilities": {"structured_outputs": {"supported": true}}
            },
            {
                "id": "claude-haiku-test",
                "type": "model",
                "created_at": "2026-06-01T00:00:00Z",
                "display_name": "Claude Haiku Test",
                "max_input_tokens": 0,
                "max_tokens": 0
            }
        ],
        "first_id": "claude-sonnet-test",
        "has_more": true,
        "last_id": "claude-haiku-test"
    })
    .to_string();
    let (base_url, capture, server) = serve_model_list("200 OK", &anthropic_body);
    let output = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home.path())
        .args([
            "config",
            "provider-models-anthropic",
            "--base-url",
            &base_url,
            "--credential-env",
            "MEALY_TEST_ANTHROPIC_DISCOVERY_CREDENTIAL",
            "--contains",
            "sonnet",
            "--limit",
            "2",
            "--after-id",
            "previous/model",
        ])
        .env(
            "MEALY_TEST_ANTHROPIC_DISCOVERY_CREDENTIAL",
            "anthropic-discovery-secret",
        )
        .output()
        .expect("run Anthropic model discovery");
    assert!(
        output.status.success(),
        "Anthropic model discovery failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("anthropic-discovery-secret"));
    let response: Value = serde_json::from_slice(&output.stdout).expect("discovery response");
    assert_eq!(response["protocol"], "anthropic_messages");
    assert_eq!(response["providerHasMore"], true);
    assert_eq!(response["nextAfterId"], "claude-haiku-test");
    assert_eq!(response["models"][0]["id"], "claude-sonnet-test");
    assert_eq!(response["models"][0]["contextTokens"], 200_000);
    assert_eq!(response["models"][0]["maximumOutputTokens"], 64000);
    assert_eq!(response["models"][0]["tokenLimitsComplete"], true);
    let request = capture.recv().expect("captured Anthropic model request");
    assert!(request.starts_with("GET /v1/models?limit=2&after_id=previous%2Fmodel HTTP/1.1\r\n"));
    assert!(request.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("x-api-key") && value.trim() == "anthropic-discovery-secret"
        })
    }));
    assert!(request.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("anthropic-version") && value.trim() == "2023-06-01"
        })
    }));
    server.join().expect("Anthropic discovery server");

    let openrouter_body = json!({
        "data": [
            {
                "id": "anthropic/claude-test",
                "name": "Claude Test ",
                "created": 50,
                "context_length": 180_000,
                "pricing": {
                    "prompt": "0.000003",
                    "completion": "0.000015",
                    "request": "0",
                    "image": "0",
                    "web_search": "0",
                    "internal_reasoning": "0",
                    "input_cache_read": "0",
                    "input_cache_write": "0"
                },
                "supported_parameters": ["max_tokens", "tools", "tool_choice"],
                "architecture": {"output_modalities": ["text"]},
                "top_provider": {"context_length": 200_000, "max_completion_tokens": 64_000}
            },
            {
                "id": "vendor/no-tools",
                "name": "No Tools",
                "created": 40,
                "context_length": 4096,
                "pricing": {"prompt": "0", "completion": "0"},
                "supported_parameters": ["max_tokens"],
                "architecture": {"output_modalities": ["text"]},
                "top_provider": null
            }
        ]
    })
    .to_string();
    let (base_url, capture, server) = serve_model_list("200 OK", &openrouter_body);
    let output = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home.path())
        .args([
            "config",
            "provider-models-openrouter",
            "--base-url",
            &base_url,
            "--credential-env",
            "MEALY_TEST_OPENROUTER_DISCOVERY_CREDENTIAL",
        ])
        .env(
            "MEALY_TEST_OPENROUTER_DISCOVERY_CREDENTIAL",
            "openrouter-discovery-secret",
        )
        .output()
        .expect("run OpenRouter model discovery");
    assert!(
        output.status.success(),
        "OpenRouter model discovery failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("openrouter-discovery-secret"));
    let response: Value = serde_json::from_slice(&output.stdout).expect("discovery response");
    assert_eq!(response["protocol"], "openrouter_responses_beta");
    assert_eq!(response["pricingIncluded"], true);
    assert_eq!(response["returnedCount"], 1);
    assert_eq!(response["models"][0]["id"], "anthropic/claude-test");
    assert_eq!(response["models"][0]["displayName"], "Claude Test");
    assert_eq!(response["models"][0]["contextTokens"], 200_000);
    assert_eq!(response["models"][0]["maximumOutputTokens"], 64_000);
    assert_eq!(
        response["models"][0]["inputMicrounitsPerMillionTokens"],
        3_000_000
    );
    assert_eq!(
        response["models"][0]["outputMicrounitsPerMillionTokens"],
        15_000_000
    );
    assert_eq!(response["models"][0]["pricingComplete"], true);
    assert_eq!(response["models"][0]["toolCapable"], true);
    let request = capture.recv().expect("captured OpenRouter model request");
    assert!(request.starts_with("GET /v1/models/user HTTP/1.1\r\n"));
    assert!(request.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("authorization")
                && value.trim() == "Bearer openrouter-discovery-secret"
        })
    }));
    server.join().expect("OpenRouter discovery server");

    let local_body = json!({
        "object": "list",
        "data": [
            {"id": "local-reasoner", "object": "model", "created": 40, "owned_by": "local"}
        ]
    })
    .to_string();
    let (base_url, capture, server) = serve_model_list("200 OK", &local_body);
    let output = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home.path())
        .args(["config", "provider-models-local", "--base-url", &base_url])
        .output()
        .expect("run local model discovery");
    assert!(
        output.status.success(),
        "local model discovery failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).expect("local discovery response");
    assert_eq!(response["models"][0]["id"], "local-reasoner");
    assert_eq!(response["pricingIncluded"], false);
    assert!(
        response["metadataNotice"]
            .as_str()
            .is_some_and(|notice| notice.contains("bounded activation probe"))
    );
    let request = capture.recv().expect("captured local model request");
    assert!(request.starts_with("GET /v1/models HTTP/1.1\r\n"));
    assert!(!request.lines().any(|line| {
        line.split_once(':')
            .is_some_and(|(name, _)| name.eq_ignore_ascii_case("authorization"))
    }));
    server.join().expect("local discovery server");

    assert!(!home.path().join("config.json").exists());
    assert!(!home.path().join("provider-secrets").exists());
}

#[test]
fn provider_model_discovery_does_not_echo_failure_body_or_credential() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    let (base_url, _capture, server) =
        serve_model_list("401 Unauthorized", "sensitive discovery failure");
    let output = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home.path())
        .args([
            "config",
            "provider-models",
            "--base-url",
            &base_url,
            "--credential-env",
            "MEALY_TEST_DISCOVERY_CREDENTIAL",
        ])
        .env(
            "MEALY_TEST_DISCOVERY_CREDENTIAL",
            "rejected-discovery-secret",
        )
        .output()
        .expect("run failed model discovery");
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("HTTP status 401"));
    assert!(!error.contains("sensitive discovery failure"));
    assert!(!error.contains("rejected-discovery-secret"));
    server.join().expect("rejected discovery server");
}

#[test]
#[cfg(unix)]
#[allow(clippy::too_many_lines)]
fn subscription_provider_activation_pins_official_client_and_clears_api_keys() {
    use std::os::unix::fs::PermissionsExt as _;

    let cases = [
        (
            "provider-subscription-openai",
            "chatgpt-subscription",
            "openai_subscription_cli",
            "open_ai_codex",
            "openai.subscription",
            concat!(
                "#!/bin/sh\n",
                "test -z \"${OPENAI_API_KEY:-}${ANTHROPIC_API_KEY:-}${OPENROUTER_API_KEY:-}${LOCAL_API_KEY:-}\" || exit 90\n",
                "cat >/dev/null\n",
                "printf '%s\\n' ",
                "'{\"type\":\"thread.started\",\"thread_id\":\"fixture-request\"}' ",
                "'{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"{\\\"kind\\\":\\\"final\\\",\\\"text\\\":\\\"OK\\\",\\\"toolId\\\":null,\\\"arguments\\\":null}\"}}' ",
                "'{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}'\n",
            ),
        ),
        (
            "provider-subscription-claude",
            "claude-subscription",
            "claude_subscription_cli",
            "anthropic_claude",
            "claude.subscription",
            concat!(
                "#!/bin/sh\n",
                "test -z \"${OPENAI_API_KEY:-}${ANTHROPIC_API_KEY:-}${OPENROUTER_API_KEY:-}${LOCAL_API_KEY:-}\" || exit 90\n",
                "cat >/dev/null\n",
                "printf '%s\\n' ",
                "'{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"result\":\"{\\\"kind\\\":\\\"final\\\",\\\"text\\\":\\\"OK\\\",\\\"toolId\\\":null,\\\"arguments\\\":null}\",\"session_id\":\"fixture-request\",\"usage\":{\"input_tokens\":10,\"cache_creation_input_tokens\":0,\"cache_read_input_tokens\":0,\"output_tokens\":5},\"modelUsage\":{\"fixture-model\":{}}}'\n",
            ),
        ),
    ];

    for (command, onboarding_route, protocol, client, provider_id, fixture_body) in cases {
        let home = tempfile::tempdir().expect("temporary subscription home");
        fs::create_dir(home.path().join("config-history")).expect("configuration history");
        fs::write(
            home.path().join("config.json"),
            serde_json::to_vec_pretty(&default_config()).expect("encode default config"),
        )
        .expect("write default config");
        let executable = home.path().join(format!("{command}-fixture"));
        fs::write(&executable, fixture_body).expect("write subscription fixture");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("make subscription fixture executable");
        let executable = executable
            .canonicalize()
            .expect("canonical subscription fixture");
        let executable_digest = sha256_digest(fixture_body.as_bytes());

        let output = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
            .arg("--home")
            .arg(home.path())
            .args(["config", command, "--executable-path"])
            .arg(&executable)
            .args([
                "--model",
                "fixture-model",
                "--context-tokens",
                "32768",
                "--maximum-output-tokens",
                "64",
                "--approve",
            ])
            .env("OPENAI_API_KEY", "must-not-reach-official-client")
            .env("ANTHROPIC_API_KEY", "must-not-reach-official-client")
            .env("OPENROUTER_API_KEY", "must-not-reach-official-client")
            .env("LOCAL_API_KEY", "must-not-reach-official-client")
            .output()
            .expect("activate subscription provider");
        assert!(
            output.status.success(),
            "{command} activation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let response: Value = serde_json::from_slice(&output.stdout).expect("activation response");
        assert_eq!(response["protocol"], protocol);
        assert_eq!(response["providerId"], provider_id);
        assert_eq!(response["connectivityTested"], true);
        assert_eq!(response["secretId"], Value::Null);

        let config: Value = serde_json::from_slice(
            &fs::read(home.path().join("config.json")).expect("subscription config"),
        )
        .expect("subscription config JSON");
        assert_eq!(config["provider"]["kind"], "subscription_cli");
        assert_eq!(config["provider"]["client"], client);
        assert_eq!(
            config["provider"]["executablePath"],
            executable.to_str().expect("UTF-8 fixture path")
        );
        assert_eq!(config["provider"]["executableSha256"], executable_digest);
        assert_eq!(config["provider"]["model"], "fixture-model");
        assert_eq!(config["agentLoopLimits"]["providerTimeoutMs"], 65_000);
        assert!(!home.path().join("provider-secrets").exists());

        let onboard_home = tempfile::tempdir().expect("temporary subscription onboarding home");
        let output = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
            .arg("--home")
            .arg(onboard_home.path())
            .args(["onboard", "--route", onboarding_route, "--executable-path"])
            .arg(&executable)
            .args([
                "--model",
                "fixture-model",
                "--context-tokens",
                "32768",
                "--maximum-output-tokens",
                "64",
                "--configure-only",
                "--approve",
            ])
            .env("OPENAI_API_KEY", "must-not-reach-official-client")
            .env("ANTHROPIC_API_KEY", "must-not-reach-official-client")
            .env("OPENROUTER_API_KEY", "must-not-reach-official-client")
            .env("LOCAL_API_KEY", "must-not-reach-official-client")
            .output()
            .expect("onboard subscription provider");
        assert!(
            output.status.success(),
            "{onboarding_route} onboarding failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let response: Value = serde_json::from_slice(&output.stdout).expect("onboarding response");
        assert_eq!(response["provider"]["protocol"], protocol);
        assert_eq!(response["provider"]["providerId"], provider_id);
        assert_eq!(response["provider"]["connectivityTested"], true);
        assert_eq!(response["provider"]["secretId"], Value::Null);
        assert_eq!(response["service"], Value::Null);
        assert_eq!(response["serviceStarted"], false);
        assert_eq!(response["chatStarted"], false);
        let config: Value = serde_json::from_slice(
            &fs::read(onboard_home.path().join("config.json"))
                .expect("subscription onboarding config"),
        )
        .expect("subscription onboarding JSON");
        assert_eq!(config["provider"]["client"], client);
        assert_eq!(config["provider"]["executableSha256"], executable_digest);
        assert!(!onboard_home.path().join("provider-secrets").exists());
    }
}

#[test]
fn guided_setup_initializes_a_clean_home_probes_brokers_and_prints_exact_handoff() {
    let home = tempfile::tempdir().expect("clean temporary Mealy home");
    let completed = json!({
        "id": "resp-guided-setup",
        "object": "response",
        "model": "guided-model",
        "status": "completed",
        "output": [{
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "OK"}]
        }]
    });
    let event = json!({"type": "response.completed", "response": completed});
    let (base_url, capture, server) = serve_probe(
        "200 OK",
        "text/event-stream",
        format!("event: response.completed\ndata: {event}\n\ndata: [DONE]\n\n"),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home.path())
        .args([
            "setup",
            "--provider",
            "openai",
            "--base-url",
            &base_url,
            "--model",
            "guided-model",
            "--context-tokens",
            "32768",
            "--credential-env",
            "MEALY_TEST_GUIDED_SETUP_KEY",
            "--input-microunits-per-million-tokens",
            "2500000",
            "--output-microunits-per-million-tokens",
            "10000000",
            "--approve",
        ])
        .env("MEALY_TEST_GUIDED_SETUP_KEY", "guided-setup-secret")
        .output()
        .expect("run clean-home setup wizard");
    assert!(
        output.status.success(),
        "guided setup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 setup JSON");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 setup handoff");
    assert!(!stdout.contains("guided-setup-secret"));
    assert!(!stderr.contains("guided-setup-secret"));
    let response: Value = serde_json::from_str(&stdout).expect("setup activation response");
    assert_eq!(response["providerId"], "openai.responses");
    assert_eq!(response["model"], "guided-model");
    assert_eq!(response["connectivityTested"], true);
    assert!(stderr.contains("Setup complete"));
    assert!(stderr.contains("mealyd --home"));
    assert!(stderr.contains("mealyctl --home"));
    assert!(stderr.contains("doctor"));
    assert!(stderr.contains("chat"));

    let configured: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("initialized configuration"),
    )
    .expect("configured JSON");
    assert_eq!(configured["provider"]["kind"], "open_ai_responses");
    assert_eq!(configured["agentLoopLimits"]["providerTimeoutMs"], 35_000);
    assert_eq!(
        configured["provider"]["credential"]["secretId"],
        "openai-primary"
    );
    assert!(!configured.to_string().contains("guided-setup-secret"));
    assert!(home.path().join("config-history").is_dir());
    assert_eq!(
        FileProviderSecretStore::new(home.path().join("provider-secrets"))
            .expect("provider broker")
            .read("openai-primary")
            .expect("brokered setup key")
            .as_str(),
        "guided-setup-secret"
    );
    let (headers, body) = capture.recv().expect("captured setup probe");
    assert!(headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("authorization")
                && value.trim() == "Bearer guided-setup-secret"
        })
    }));
    assert_eq!(body["model"], "guided-model");
    assert_eq!(body["store"], false);
    assert_eq!(body["max_output_tokens"], 256);
    server.join().expect("guided setup probe server");
}

#[test]
fn guided_setup_interactively_selects_local_model_and_requires_exact_approval() {
    let home = tempfile::tempdir().expect("clean local setup home");
    let mut child = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home.path())
        .args(["setup", "--skip-connectivity-test"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn interactive setup");
    child
        .stdin
        .take()
        .expect("interactive setup stdin")
        .write_all(b"4\nlocal-guided-model\n32768\nAPPROVE\n")
        .expect("answer setup prompts");
    let output = child.wait_with_output().expect("collect interactive setup");
    assert!(
        output.status.success(),
        "interactive setup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).expect("setup JSON");
    assert_eq!(response["providerId"], "local.responses");
    assert_eq!(response["model"], "local-guided-model");
    assert_eq!(response["secretId"], Value::Null);
    assert_eq!(response["connectivityTested"], false);
    let prompt = String::from_utf8_lossy(&output.stderr);
    assert!(prompt.contains("Select a provider"));
    assert!(prompt.contains("Type APPROVE"));
    assert!(prompt.contains("SKIPPED (staged, not production-verified)"));
    let config: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("local setup config"),
    )
    .expect("local setup JSON");
    assert_eq!(config["provider"]["credential"], Value::Null);
    assert!(!home.path().join("provider-secrets").exists());

    let denied_home = tempfile::tempdir().expect("denied setup home");
    let mut denied = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(denied_home.path())
        .args(["setup", "--skip-connectivity-test"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn denied setup");
    denied
        .stdin
        .take()
        .expect("denied setup stdin")
        .write_all(b"4\nlocal-guided-model\n32768\nNO\n")
        .expect("deny setup");
    let denied = denied.wait_with_output().expect("collect denied setup");
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("was not approved"));
    assert!(!denied_home.path().join("config.json").exists());
}

#[test]
fn onboarding_configures_a_clean_home_and_refuses_silent_replacement() {
    let home = tempfile::tempdir().expect("clean onboarding home");
    let arguments = [
        "onboard",
        "--route",
        "local",
        "--model",
        "local-onboarding-model",
        "--context-tokens",
        "32768",
        "--maximum-output-tokens",
        "2048",
        "--skip-connectivity-test",
        "--configure-only",
        "--approve",
    ];
    let output = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home.path())
        .args(arguments)
        .output()
        .expect("run clean-home onboarding");
    assert!(
        output.status.success(),
        "onboarding failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).expect("onboarding response");
    assert_eq!(response["provider"]["providerId"], "local.responses");
    assert_eq!(response["provider"]["model"], "local-onboarding-model");
    assert_eq!(response["provider"]["connectivityTested"], false);
    assert_eq!(response["service"], Value::Null);
    assert_eq!(response["serviceStarted"], false);
    assert_eq!(response["healthVerified"], false);
    assert_eq!(response["chatStarted"], false);
    assert!(
        response["nextCommand"]
            .as_str()
            .is_some_and(|command| command.contains("service install"))
    );
    let prompt = String::from_utf8_lossy(&output.stderr);
    assert!(prompt.contains("Review the exact non-secret onboarding plan"));
    assert!(prompt.contains("Service installation was intentionally skipped"));

    let configured = fs::read(home.path().join("config.json")).expect("configured home");
    let second = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home.path())
        .args(arguments)
        .output()
        .expect("rerun onboarding without reconfigure");
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("already has configuration"));
    assert_eq!(
        fs::read(home.path().join("config.json")).expect("unchanged configuration"),
        configured
    );
}

#[test]
fn implicit_home_survives_working_directory_changes_and_honors_overrides() {
    let owner = tempfile::tempdir().expect("temporary owner home");
    let first_directory = tempfile::tempdir().expect("first working directory");
    let second_directory = tempfile::tempdir().expect("second working directory");
    let arguments = [
        "onboard",
        "--route",
        "local",
        "--model",
        "stable-home-model",
        "--context-tokens",
        "32768",
        "--skip-connectivity-test",
        "--configure-only",
        "--approve",
    ];
    let configured = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .current_dir(first_directory.path())
        .env("HOME", owner.path())
        .env_remove("MEALY_HOME")
        .args(arguments)
        .output()
        .expect("configure implicit owner home");
    assert!(
        configured.status.success(),
        "implicit-home onboarding failed: {}",
        String::from_utf8_lossy(&configured.stderr)
    );

    let expected_home = owner.path().join(".mealy");
    assert!(expected_home.join("config.json").is_file());
    assert!(!first_directory.path().join(".mealy").exists());
    assert!(!second_directory.path().join(".mealy").exists());

    let listed = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .current_dir(second_directory.path())
        .env("HOME", owner.path())
        .env_remove("MEALY_HOME")
        .args(["config", "provider-list"])
        .output()
        .expect("read implicit owner home from another directory");
    assert!(
        listed.status.success(),
        "cross-directory provider read failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let response: Value = serde_json::from_slice(&listed.stdout).expect("provider-list response");
    assert_eq!(response["primary"]["model"], "stable-home-model");

    let explicit_home = owner.path().join("alternate");
    let explicit = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .current_dir(second_directory.path())
        .env_remove("HOME")
        .env_remove("MEALY_HOME")
        .arg("--home")
        .arg(&explicit_home)
        .args(arguments)
        .output()
        .expect("configure explicit home without HOME");
    assert!(
        explicit.status.success(),
        "explicit-home onboarding failed: {}",
        String::from_utf8_lossy(&explicit.stderr)
    );
    assert!(explicit_home.join("config.json").is_file());

    let environment_home = owner.path().join("environment-override");
    let environment = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .current_dir(second_directory.path())
        .env("HOME", owner.path())
        .env("MEALY_HOME", &environment_home)
        .args(arguments)
        .output()
        .expect("configure MEALY_HOME override");
    assert!(
        environment.status.success(),
        "MEALY_HOME onboarding failed: {}",
        String::from_utf8_lossy(&environment.stderr)
    );
    assert!(environment_home.join("config.json").is_file());

    let missing_default = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .current_dir(second_directory.path())
        .env_remove("HOME")
        .env_remove("MEALY_HOME")
        .args(["config", "provider-list"])
        .output()
        .expect("reject missing default home");
    assert!(!missing_default.status.success());
    assert!(
        String::from_utf8_lossy(&missing_default.stderr)
            .contains("could not determine the default Mealy home")
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn onboarding_openrouter_free_route_discovers_and_probes_only_exact_free_metadata() {
    let home = tempfile::tempdir().expect("clean OpenRouter onboarding home");
    let catalog = json!({
        "data": [
            {
                "id": "vendor/tool-model:free",
                "name": "Tool Model Free",
                "created": 50,
                "context_length": 32768,
                "pricing": {
                    "prompt": "0",
                    "completion": "0",
                    "request": "0",
                    "image": "0",
                    "web_search": "0",
                    "internal_reasoning": "0",
                    "input_cache_read": "0",
                    "input_cache_write": "0"
                },
                "supported_parameters": ["max_tokens", "tools"],
                "architecture": {"output_modalities": ["text"]},
                "top_provider": {
                    "context_length": 32768,
                    "max_completion_tokens": 8192
                }
            },
            {
                "id": "vendor/paid-model",
                "name": "Paid Model",
                "created": 40,
                "context_length": 32768,
                "pricing": {"prompt": "0.000001", "completion": "0.000002"},
                "supported_parameters": ["max_tokens", "tools"],
                "architecture": {"output_modalities": ["text"]},
                "top_provider": {
                    "context_length": 32768,
                    "max_completion_tokens": 8192
                }
            }
        ]
    })
    .to_string();
    let completed = json!({
        "id": "resp-openrouter-onboarding",
        "object": "response",
        "model": "vendor/tool-model:free",
        "status": "completed",
        "output": [{
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "OK"}]
        }]
    });
    let event = json!({"type": "response.completed", "response": completed});
    let probe = format!("event: response.completed\ndata: {event}\n\ndata: [DONE]\n\n");
    let (base_url, capture, server) = serve_openrouter_onboarding(catalog, probe);
    let output = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home.path())
        .args([
            "onboard",
            "--route",
            "openrouter-free",
            "--base-url",
            &base_url,
            "--model",
            "vendor/tool-model:free",
            "--credential-env",
            "MEALY_TEST_ONBOARD_OPENROUTER_KEY",
            "--configure-only",
            "--approve",
        ])
        .env(
            "MEALY_TEST_ONBOARD_OPENROUTER_KEY",
            "openrouter-onboarding-secret",
        )
        .output()
        .expect("run OpenRouter free onboarding");
    assert!(
        output.status.success(),
        "OpenRouter onboarding failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("openrouter-onboarding-secret"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("openrouter-onboarding-secret"));
    let response: Value = serde_json::from_slice(&output.stdout).expect("onboarding response");
    assert_eq!(response["provider"]["providerId"], "openrouter.responses");
    assert_eq!(response["provider"]["model"], "vendor/tool-model:free");
    assert_eq!(response["provider"]["connectivityTested"], true);
    let config: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("OpenRouter config"),
    )
    .expect("OpenRouter config JSON");
    assert_eq!(config["provider"]["contextTokens"], 32768);
    assert_eq!(config["provider"]["maximumOutputTokens"], 4096);
    assert_eq!(config["provider"]["inputMicrounitsPerMillionTokens"], 0);
    assert_eq!(config["provider"]["outputMicrounitsPerMillionTokens"], 0);
    let requests = capture.recv().expect("captured onboarding requests");
    assert!(
        requests[0]
            .0
            .starts_with("GET /v1/models/user HTTP/1.1\r\n")
    );
    assert!(requests[1].0.starts_with("POST /v1/responses HTTP/1.1\r\n"));
    assert_eq!(
        requests[1].1.as_ref().expect("probe JSON")["model"],
        "vendor/tool-model:free"
    );
    assert_eq!(
        requests[1].1.as_ref().expect("probe JSON")["max_output_tokens"],
        256
    );
    assert!(
        requests
            .iter()
            .all(|(headers, _)| headers.lines().any(|line| {
                line.split_once(':').is_some_and(|(name, value)| {
                    name.eq_ignore_ascii_case("authorization")
                        && value.trim() == "Bearer openrouter-onboarding-secret"
                })
            }))
    );
    server.join().expect("OpenRouter onboarding server");
}

#[test]
fn provider_activation_runs_bounded_streaming_probe_and_fails_atomically() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    fs::create_dir(home.path().join("config-history")).expect("configuration history");
    fs::write(
        home.path().join("config.json"),
        serde_json::to_vec_pretty(&default_config()).expect("encode default config"),
    )
    .expect("write default config");
    let completed = json!({
        "id": "resp-provider-probe",
        "object": "response",
        "model": "test-model",
        "status": "completed",
        "output": [{
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "OK"}]
        }]
    });
    let event = json!({"type": "response.completed", "response": completed});
    let (base_url, capture, server) = serve_probe(
        "200 OK",
        "text/event-stream",
        format!("event: response.completed\ndata: {event}\n\ndata: [DONE]\n\n"),
    );
    let output = configure_live(home.path(), &base_url, "live-probe-secret");
    assert!(
        output.status.success(),
        "provider probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output
            .stdout
            .windows("live-probe-secret".len())
            .any(|window| { window == b"live-probe-secret" })
    );
    let response: Value = serde_json::from_slice(&output.stdout).expect("probe response");
    assert_eq!(response["connectivityTested"], true);
    assert_eq!(response["streaming"], true);
    let (headers, body) = capture.recv().expect("captured provider probe");
    assert!(headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("authorization") && value.trim() == "Bearer live-probe-secret"
        })
    }));
    assert!(headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("accept") && value.trim() == "text/event-stream"
        })
    }));
    assert_eq!(body["model"], "test-model");
    assert_eq!(body["stream"], true);
    assert_eq!(body["store"], false);
    assert_eq!(body["max_output_tokens"], 256);
    server.join().expect("probe server");

    let failed_home = tempfile::tempdir().expect("failed probe home");
    fs::create_dir(failed_home.path().join("config-history")).expect("configuration history");
    fs::write(
        failed_home.path().join("config.json"),
        serde_json::to_vec_pretty(&default_config()).expect("encode default config"),
    )
    .expect("write default config");
    let (base_url, _capture, server) = serve_probe(
        "401 Unauthorized",
        "application/json",
        "{\"sensitive\":\"do-not-echo\"}".to_owned(),
    );
    let failed = configure_live(failed_home.path(), &base_url, "rejected-probe-secret");
    assert!(!failed.status.success());
    let error = String::from_utf8_lossy(&failed.stderr);
    assert!(error.contains("HTTP status 401"));
    assert!(!error.contains("rejected-probe-secret"));
    assert!(!error.contains("do-not-echo"));
    let unchanged: Value = serde_json::from_slice(
        &fs::read(failed_home.path().join("config.json")).expect("unchanged config"),
    )
    .expect("unchanged JSON");
    assert_eq!(unchanged["provider"]["kind"], "builtin_fixture");
    assert!(
        !failed_home
            .path()
            .join("provider-secrets/test-primary.key")
            .exists()
    );
    server.join().expect("rejected probe server");
}

#[test]
fn provider_activation_rejects_a_wrong_terminal_model_before_publication() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    fs::create_dir(home.path().join("config-history")).expect("configuration history");
    fs::write(
        home.path().join("config.json"),
        serde_json::to_vec_pretty(&default_config()).expect("encode default config"),
    )
    .expect("write default config");
    let completed = json!({
        "id": "resp-wrong-model",
        "object": "response",
        "model": "SECRET-WRONG-MODEL",
        "status": "completed",
        "output": [{
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "OK"}]
        }]
    });
    let event = json!({"type": "response.completed", "response": completed});
    let (base_url, _capture, server) = serve_probe(
        "200 OK",
        "text/event-stream",
        format!("event: response.completed\ndata: {event}\n\ndata: [DONE]\n\n"),
    );
    let output = configure_live(home.path(), &base_url, "wrong-model-probe-secret");
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(!error.contains("SECRET-WRONG-MODEL"));
    assert!(!error.contains("wrong-model-probe-secret"));
    let unchanged: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("unchanged config"),
    )
    .expect("unchanged JSON");
    assert_eq!(unchanged["provider"]["kind"], "builtin_fixture");
    assert!(
        !home
            .path()
            .join("provider-secrets/test-primary.key")
            .exists()
    );
    server.join().expect("wrong-model probe server");
}

#[test]
fn openrouter_preset_brokers_key_and_proves_stateless_responses_beta_shape() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    fs::create_dir(home.path().join("config-history")).expect("configuration history");
    fs::write(
        home.path().join("config.json"),
        serde_json::to_vec_pretty(&default_config()).expect("encode default config"),
    )
    .expect("write default config");
    let completed = json!({
        "id": "resp-openrouter-probe",
        "object": "response",
        "model": "anthropic/claude-test",
        "status": "completed",
        "output": [{
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "OK"}]
        }]
    });
    let event = json!({"type": "response.completed", "response": completed});
    let (base_url, capture, server) = serve_probe(
        "200 OK",
        "text/event-stream",
        format!("event: response.completed\ndata: {event}\n\ndata: [DONE]\n\n"),
    );
    let output = configure_openrouter_live(home.path(), &base_url, "openrouter-probe-secret");
    assert!(
        output.status.success(),
        "OpenRouter probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("openrouter-probe-secret"));
    let response: Value = serde_json::from_slice(&output.stdout).expect("activation response");
    assert_eq!(response["providerId"], "test.openrouter.responses");
    assert_eq!(response["protocol"], "openai_responses");
    assert_eq!(response["connectivityTested"], true);
    let (headers, body) = capture.recv().expect("captured OpenRouter probe");
    assert!(headers.starts_with("POST /v1/responses HTTP/1.1\r\n"));
    assert!(headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("authorization")
                && value.trim() == "Bearer openrouter-probe-secret"
        })
    }));
    assert_eq!(body["model"], "anthropic/claude-test");
    assert_eq!(body["stream"], true);
    assert_eq!(body["store"], false);
    assert_eq!(body["max_output_tokens"], 256);
    assert!(body["previous_response_id"].is_null());
    server.join().expect("OpenRouter probe server");

    let configured: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("configured document"),
    )
    .expect("configured JSON");
    assert_eq!(configured["provider"]["kind"], "open_ai_responses");
    assert_eq!(configured["provider"]["baseUrl"], base_url);
    assert_eq!(configured["provider"]["residency"], "openrouter-test");
    assert_eq!(
        configured["provider"]["inputMicrounitsPerMillionTokens"],
        3_000_000
    );
    assert_eq!(
        FileProviderSecretStore::new(home.path().join("provider-secrets"))
            .expect("provider broker")
            .read("openrouter-primary")
            .expect("brokered OpenRouter key")
            .as_str(),
        "openrouter-probe-secret"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn credentialless_local_provider_is_probed_without_auth_and_rejects_remote_endpoints() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    fs::create_dir(home.path().join("config-history")).expect("configuration history");
    fs::write(
        home.path().join("config.json"),
        serde_json::to_vec_pretty(&default_config()).expect("encode default config"),
    )
    .expect("write default config");
    let completed = json!({
        "id": "resp-local-provider-probe",
        "object": "response",
        "model": "local-model",
        "status": "completed",
        "output": [{
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "OK"}]
        }]
    });
    let event = json!({"type": "response.completed", "response": completed});
    let (base_url, capture, server) = serve_probe(
        "200 OK",
        "text/event-stream",
        format!("event: response.completed\ndata: {event}\n\ndata: [DONE]\n\n"),
    );
    let output = configure_local(home.path(), &base_url, false);
    assert!(
        output.status.success(),
        "local provider probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).expect("local response");
    assert_eq!(response["protocol"], "openai_responses");
    assert_eq!(response["secretId"], Value::Null);
    assert_eq!(response["connectivityTested"], true);
    let (headers, body) = capture.recv().expect("captured local provider probe");
    assert!(!headers.lines().any(|line| {
        line.split_once(':')
            .is_some_and(|(name, _)| name.eq_ignore_ascii_case("authorization"))
    }));
    assert_eq!(body["model"], "local-model");
    assert_eq!(body["stream"], true);
    server.join().expect("local probe server");

    let configured: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("configured document"),
    )
    .expect("configured JSON");
    assert_eq!(configured["provider"]["credential"], Value::Null);
    assert_eq!(configured["provider"]["residency"], "local");
    assert_eq!(configured["provider"]["inputMicrounitsPerMillionTokens"], 0);
    assert_eq!(
        configured["provider"]["outputMicrounitsPerMillionTokens"],
        0
    );
    assert_eq!(configured["agentLoopLimits"]["providerTimeoutMs"], 65_000);
    assert!(!home.path().join("provider-secrets").exists());

    let fallback = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home.path())
        .args([
            "config",
            "provider-fallback-local",
            "--base-url",
            &base_url,
            "--model",
            "local-fallback-model",
            "--context-tokens",
            "32768",
            "--skip-connectivity-test",
            "--approve",
        ])
        .output()
        .expect("configure local fallback");
    assert!(
        fallback.status.success(),
        "local fallback failed: {}",
        String::from_utf8_lossy(&fallback.stderr)
    );
    let fallback_response: Value =
        serde_json::from_slice(&fallback.stdout).expect("local fallback response");
    assert_eq!(fallback_response["secretId"], Value::Null);
    assert_eq!(fallback_response["providerRole"], "fallback");
    let configured: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("fallback document"),
    )
    .expect("fallback JSON");
    assert_eq!(
        configured["providerFallbacks"][0]["credential"],
        Value::Null
    );
    assert!(!home.path().join("provider-secrets").exists());

    let rejected_home = tempfile::tempdir().expect("rejected local home");
    fs::create_dir(rejected_home.path().join("config-history")).expect("configuration history");
    fs::write(
        rejected_home.path().join("config.json"),
        serde_json::to_vec_pretty(&default_config()).expect("encode default config"),
    )
    .expect("write default config");
    let rejected = configure_local(
        rejected_home.path(),
        "https://provider.example.test/v1",
        true,
    );
    assert!(!rejected.status.success());
    let unchanged: Value = serde_json::from_slice(
        &fs::read(rejected_home.path().join("config.json")).expect("unchanged document"),
    )
    .expect("unchanged JSON");
    assert_eq!(unchanged["provider"]["kind"], "builtin_fixture");
    assert!(!rejected_home.path().join("provider-secrets").exists());
}

#[test]
fn anthropic_activation_runs_its_distinct_bounded_streaming_probe() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    fs::create_dir(home.path().join("config-history")).expect("configuration history");
    fs::write(
        home.path().join("config.json"),
        serde_json::to_vec_pretty(&default_config()).expect("encode default config"),
    )
    .expect("write default config");
    let events = [
        json!({
            "type": "message_start",
            "message": {
                "id": "msg-provider-probe",
                "type": "message",
                "role": "assistant",
                "model": "test-claude-model",
                "content": [],
                "stop_reason": null,
                "usage": {"input_tokens": 10, "output_tokens": 0}
            }
        }),
        json!({
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "text", "text": ""}
        }),
        json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": "OK"}
        }),
        json!({"type": "content_block_stop", "index": 0}),
        json!({
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn", "stop_sequence": null},
            "usage": {"output_tokens": 1}
        }),
        json!({"type": "message_stop"}),
    ];
    let mut body = String::new();
    for event in &events {
        writeln!(body, "event: {}\ndata: {event}\n", event["type"]).expect("encode SSE");
    }
    let (base_url, capture, server) = serve_probe("200 OK", "text/event-stream", body);
    let output = configure_anthropic_live(home.path(), &base_url, "anthropic-probe-secret");
    assert!(
        output.status.success(),
        "Anthropic provider probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("anthropic-probe-secret"));
    let response: Value = serde_json::from_slice(&output.stdout).expect("probe response");
    assert_eq!(response["protocol"], "anthropic_messages");
    assert_eq!(response["connectivityTested"], true);
    assert_eq!(response["streaming"], true);
    let (headers, body) = capture.recv().expect("captured provider probe");
    assert!(headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("x-api-key") && value.trim() == "anthropic-probe-secret"
        })
    }));
    assert!(headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("anthropic-version") && value.trim() == "2023-06-01"
        })
    }));
    assert_eq!(body["model"], "test-claude-model");
    assert_eq!(body["stream"], true);
    assert_eq!(body["max_tokens"], 256);
    assert!(body.get("input").is_none());
    assert!(body.get("store").is_none());
    let configured: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("configured document"),
    )
    .expect("configured JSON");
    assert_eq!(configured["provider"]["kind"], "anthropic_messages");
    assert_eq!(configured["provider"]["credential"]["source"], "broker");
    assert!(!configured.to_string().contains("anthropic-probe-secret"));
    assert_eq!(
        fs::read(home.path().join("provider-secrets/anthropic-primary.key"))
            .expect("brokered Anthropic credential"),
        b"anthropic-probe-secret"
    );
    server.join().expect("probe server");
}

#[test]
fn provider_secret_revocation_requires_stopped_unreferenced_explicit_authority() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    fs::create_dir(home.path().join("config-history")).expect("configuration history");
    let mut config = default_config();
    config["provider"] = json!({
        "kind": "open_ai_responses",
        "providerId": "local.responses",
        "baseUrl": "http://127.0.0.1:11434/v1",
        "model": "local-model",
        "credential": {"source": "broker", "secretId": "active-provider"},
        "residency": "local",
        "contextTokens": 32_768,
        "maximumOutputTokens": 4_096,
        "streaming": false,
        "inputMicrounitsPerMillionTokens": 0,
        "outputMicrounitsPerMillionTokens": 0,
        "estimatedLatencyMs": 10
    });
    fs::write(
        home.path().join("config.json"),
        serde_json::to_vec_pretty(&config).expect("encode config"),
    )
    .expect("write config");
    let store = FileProviderSecretStore::new(home.path().join("provider-secrets"))
        .expect("provider broker");
    store
        .put("active-provider", "active-secret")
        .expect("active secret");
    store
        .put("retired-provider", "retired-secret")
        .expect("retired secret");

    let unapproved = revoke_provider_secret(home.path(), "retired-provider", false);
    assert!(!unapproved.status.success());
    assert!(store.read("retired-provider").is_ok());

    let active = revoke_provider_secret(home.path(), "active-provider", true);
    assert!(!active.status.success());
    assert!(String::from_utf8_lossy(&active.stderr).contains("still referenced"));
    assert!(store.read("active-provider").is_ok());

    let retired = revoke_provider_secret(home.path(), "retired-provider", true);
    assert!(
        retired.status.success(),
        "retired secret removal failed: {}",
        String::from_utf8_lossy(&retired.stderr)
    );
    let response: Value = serde_json::from_slice(&retired.stdout).expect("revocation response");
    assert_eq!(response["secretId"], "retired-provider");
    assert_eq!(response["removed"], true);
    assert_eq!(response["activeReferenceCheck"], "unreferenced");
    assert!(store.read("retired-provider").is_err());
    assert!(store.read("active-provider").is_ok());

    let repeated = revoke_provider_secret(home.path(), "retired-provider", true);
    assert!(repeated.status.success());
    let response: Value = serde_json::from_slice(&repeated.stdout).expect("repeat response");
    assert_eq!(response["removed"], false);
}

#[test]
#[allow(clippy::too_many_lines)]
fn config_provider_brokers_secret_and_rejects_ambiguous_rotation() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    fs::create_dir(home.path().join("config-history")).expect("configuration history");
    fs::write(
        home.path().join("config.json"),
        serde_json::to_vec_pretty(&default_config()).expect("encode default config"),
    )
    .expect("write default config");

    let first = configure(home.path(), "one-shot-provider-secret");
    assert!(
        first.status.success(),
        "provider configuration failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        !first
            .stdout
            .windows(24)
            .any(|window| { window == b"one-shot-provider-secret" })
    );
    let response: Value = serde_json::from_slice(&first.stdout).expect("configuration response");
    assert_eq!(response["providerId"], "test.responses");
    assert_eq!(response["secretId"], "test-primary");
    assert_eq!(response["providerRole"], "primary");
    assert_eq!(response["streaming"], true);
    assert_eq!(response["connectivityTested"], false);
    assert_eq!(response["restartRequired"], true);

    let config: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("configured document"),
    )
    .expect("configured JSON");
    assert_eq!(config["provider"]["kind"], "open_ai_responses");
    assert_eq!(config["provider"]["credential"]["source"], "broker");
    assert_eq!(config["provider"]["credential"]["secretId"], "test-primary");
    assert_eq!(config["provider"]["streaming"], true);
    assert!(!config.to_string().contains("one-shot-provider-secret"));

    let secret_path = home.path().join("provider-secrets/test-primary.key");
    assert_eq!(
        fs::read(&secret_path).expect("brokered credential"),
        b"one-shot-provider-secret"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&secret_path)
                .expect("secret metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let fallback = configure_fallback(home.path(), "fallback-provider-secret", "trusted-test");
    assert!(
        fallback.status.success(),
        "fallback configuration failed: {}",
        String::from_utf8_lossy(&fallback.stderr)
    );
    let fallback_response: Value =
        serde_json::from_slice(&fallback.stdout).expect("fallback response");
    assert_eq!(fallback_response["providerId"], "test-fallback.responses");
    assert_eq!(fallback_response["providerRole"], "fallback");
    assert_eq!(fallback_response["fallbackOrdinal"], 1);
    assert_eq!(fallback_response["streaming"], true);
    assert_eq!(fallback_response["connectivityTested"], false);
    let fallback_config: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("fallback document"),
    )
    .expect("fallback JSON");
    assert_eq!(
        fallback_config["providerFallbacks"][0]["providerId"],
        "test-fallback.responses"
    );
    assert_eq!(
        fallback_config["providerFallbacks"][0]["credential"]["secretId"],
        "test-fallback"
    );
    assert_eq!(fallback_config["providerFallbacks"][0]["streaming"], true);
    assert!(
        !fallback_config
            .to_string()
            .contains("fallback-provider-secret")
    );
    assert_eq!(
        fs::read(home.path().join("provider-secrets/test-fallback.key"))
            .expect("fallback credential"),
        b"fallback-provider-secret"
    );

    let anthropic = configure_anthropic_fallback(home.path(), "anthropic-fallback-secret");
    assert!(
        anthropic.status.success(),
        "Anthropic fallback configuration failed: {}",
        String::from_utf8_lossy(&anthropic.stderr)
    );
    let anthropic_response: Value =
        serde_json::from_slice(&anthropic.stdout).expect("Anthropic fallback response");
    assert_eq!(anthropic_response["protocol"], "anthropic_messages");
    assert_eq!(anthropic_response["fallbackOrdinal"], 2);
    let mixed_config: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("mixed provider document"),
    )
    .expect("mixed provider JSON");
    assert_eq!(
        mixed_config["providerFallbacks"][1]["kind"],
        "anthropic_messages"
    );
    assert_eq!(
        fs::read(
            home.path()
                .join("provider-secrets/test-anthropic-fallback.key")
        )
        .expect("Anthropic fallback credential"),
        b"anthropic-fallback-secret"
    );

    let unapproved_removal = remove_fallback(home.path(), "test-fallback.responses", false);
    assert!(!unapproved_removal.status.success());
    let unchanged: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("unchanged fallback document"),
    )
    .expect("unchanged fallback JSON");
    assert_eq!(
        unchanged["providerFallbacks"].as_array().map(Vec::len),
        Some(2)
    );

    let removed = remove_fallback(home.path(), "test-fallback.responses", true);
    assert!(
        removed.status.success(),
        "fallback removal failed: {}",
        String::from_utf8_lossy(&removed.stderr)
    );
    let removal_response: Value =
        serde_json::from_slice(&removed.stdout).expect("fallback removal response");
    assert_eq!(removal_response["providerId"], "test-fallback.responses");
    assert_eq!(removal_response["removedOrdinal"], 1);
    assert_eq!(removal_response["removedSecretId"], "test-fallback");
    assert_eq!(removal_response["credentialRetained"], true);
    assert_eq!(
        removal_response["remainingProviderIds"],
        json!(["test-fallback.anthropic"])
    );
    assert_eq!(removal_response["restartRequired"], true);
    let after_removal: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("fallback removal document"),
    )
    .expect("fallback removal JSON");
    assert_eq!(
        after_removal["providerFallbacks"][0]["providerId"],
        "test-fallback.anthropic"
    );
    assert_eq!(
        after_removal["providerFallbacks"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(
        fs::read(home.path().join("provider-secrets/test-fallback.key"))
            .expect("removed fallback credential retained"),
        b"fallback-provider-secret"
    );
    let repeated_removal = remove_fallback(home.path(), "test-fallback.responses", true);
    assert!(!repeated_removal.status.success());
    assert!(
        String::from_utf8_lossy(&repeated_removal.stderr)
            .contains("provider fallback test-fallback.responses was not found")
    );

    let rotated = configure_with_secret_id(
        home.path(),
        "rotated-primary-provider-secret",
        "test-primary-rotated",
    );
    assert!(
        rotated.status.success(),
        "primary rotation failed: {}",
        String::from_utf8_lossy(&rotated.stderr)
    );
    let rotated_config: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("rotated provider document"),
    )
    .expect("rotated provider JSON");
    assert_eq!(
        rotated_config["provider"]["credential"]["secretId"],
        "test-primary-rotated"
    );
    assert_eq!(
        rotated_config["providerFallbacks"][0]["providerId"],
        "test-fallback.anthropic"
    );
    assert_eq!(
        fs::read(
            home.path()
                .join("provider-secrets/test-primary-rotated.key")
        )
        .expect("rotated primary credential"),
        b"rotated-primary-provider-secret"
    );
    assert_eq!(
        fs::read(home.path().join("provider-secrets/test-primary.key"))
            .expect("prior primary credential retained"),
        b"one-shot-provider-secret"
    );
    let listed = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home.path())
        .args(["config", "provider-list"])
        .output()
        .expect("list provider chain");
    assert!(listed.status.success());
    let listed_response: Value =
        serde_json::from_slice(&listed.stdout).expect("provider chain response");
    assert_eq!(listed_response["primary"]["providerId"], "test.responses");
    assert_eq!(
        listed_response["primary"]["credential"]["secretId"],
        "test-primary-rotated"
    );
    assert_eq!(listed_response["fallbackCount"], 1);
    assert_eq!(
        listed_response["fallbacks"][0]["providerId"],
        "test-fallback.anthropic"
    );
    assert_eq!(listed_response["credentialValuesResolved"], false);
    assert!(!String::from_utf8_lossy(&listed.stdout).contains("rotated-primary-provider-secret"));
    let incompatible_primary = configure_primary(
        home.path(),
        "incompatible-primary-secret",
        "test-primary-incompatible",
        "different-boundary",
    );
    assert!(!incompatible_primary.status.success());
    assert!(
        !home
            .path()
            .join("provider-secrets/test-primary-incompatible.key")
            .exists()
    );
    let preserved_after_denial: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("preserved provider chain"),
    )
    .expect("preserved provider chain JSON");
    assert_eq!(
        preserved_after_denial["provider"]["credential"]["secretId"],
        "test-primary-rotated"
    );
    assert_eq!(
        preserved_after_denial["providerFallbacks"][0]["providerId"],
        "test-fallback.anthropic"
    );

    let weaker = configure_fallback(home.path(), "unused-weaker-secret", "different-boundary");
    assert!(!weaker.status.success());
    assert!(
        !home
            .path()
            .join("provider-secrets/test-fallback-2.key")
            .exists()
    );

    let conflicting = configure(home.path(), "different-provider-secret");
    assert!(!conflicting.status.success());
    let conflict_error = String::from_utf8_lossy(&conflicting.stderr);
    assert!(
        conflict_error.contains("rotate with a new secret identity"),
        "unexpected conflict error: {conflict_error}"
    );
    assert_eq!(
        fs::read(secret_path).expect("original credential retained"),
        b"one-shot-provider-secret"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn config_workspace_grant_and_revoke_are_explicit_canonical_and_reversible() {
    #[cfg(target_os = "linux")]
    let home = service_test_tempdir("mealy-home-");
    #[cfg(not(target_os = "linux"))]
    let home = tempfile::tempdir().expect("temporary Mealy home");
    #[cfg(target_os = "linux")]
    let workspace = service_test_tempdir("workspace-");
    #[cfg(not(target_os = "linux"))]
    let workspace = tempfile::tempdir().expect("workspace");
    fs::create_dir(home.path().join("config-history")).expect("configuration history");
    fs::write(
        home.path().join("config.json"),
        serde_json::to_vec_pretty(&default_config()).expect("encode default config"),
    )
    .expect("write default config");

    let unapproved = workspace_config(
        home.path(),
        "workspace-grant",
        "project",
        Some(workspace.path()),
        false,
    );
    assert!(!unapproved.status.success());
    let unchanged: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("unchanged config"),
    )
    .expect("unchanged JSON");
    assert!(unchanged.get("workspaceRoots").is_none());

    let private_root = workspace_config(
        home.path(),
        "workspace-grant",
        "private-state",
        Some(home.path()),
        true,
    );
    assert!(!private_root.status.success());
    let private_child = home.path().join("provider-secrets");
    fs::create_dir(&private_child).expect("private child");
    let private_child = workspace_config(
        home.path(),
        "workspace-grant",
        "private-child",
        Some(&private_child),
        true,
    );
    assert!(!private_child.status.success());
    let unchanged: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("private-state rejected config"),
    )
    .expect("private-state rejected JSON");
    assert!(unchanged.get("workspaceRoots").is_none());

    let granted = workspace_config(
        home.path(),
        "workspace-grant",
        "project",
        Some(workspace.path()),
        true,
    );
    assert!(
        granted.status.success(),
        "workspace grant failed: {}",
        String::from_utf8_lossy(&granted.stderr)
    );
    let grant_response: Value =
        serde_json::from_slice(&granted.stdout).expect("workspace grant response");
    assert_eq!(grant_response["workspaceId"], "project");
    assert_eq!(grant_response["operation"], "granted");
    assert_eq!(grant_response["restartRequired"], true);
    assert_eq!(grant_response["serviceReinstallRequired"], false);
    assert_eq!(
        grant_response["canonicalRoot"],
        workspace
            .path()
            .canonicalize()
            .expect("canonical workspace")
            .display()
            .to_string()
    );
    assert!(
        Path::new(
            grant_response["replacedConfigurationCopy"]
                .as_str()
                .expect("history path")
        )
        .is_file()
    );
    let configured: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("configured workspace"),
    )
    .expect("configured JSON");
    assert_eq!(configured["workspaceRoots"][0]["workspaceId"], "project");
    assert_eq!(
        configured["workspaceRoots"][0]["root"],
        workspace
            .path()
            .canonicalize()
            .expect("canonical workspace")
            .display()
            .to_string()
    );
    assert!(configured["workspaceRoots"][0].get("writable").is_none());

    let unapproved_write = workspace_config(
        home.path(),
        "workspace-write-enable",
        "project",
        None,
        false,
    );
    assert!(!unapproved_write.status.success());
    let write_enabled =
        workspace_config(home.path(), "workspace-write-enable", "project", None, true);
    assert!(
        write_enabled.status.success(),
        "workspace write enable failed: {}",
        String::from_utf8_lossy(&write_enabled.stderr)
    );
    let response: Value =
        serde_json::from_slice(&write_enabled.stdout).expect("write enable response");
    assert_eq!(response["operation"], "write_enabled");
    assert_eq!(response["serviceReinstallRequired"], false);
    let write_config: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("write-enabled workspace"),
    )
    .expect("write-enabled JSON");
    assert_eq!(write_config["workspaceRoots"][0]["writable"], true);

    #[cfg(target_os = "linux")]
    {
        let service_path = home.path().join("mealy.service");
        let service = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
            .arg("--home")
            .arg(home.path())
            .args(["service", "install", "--daemon-path", "/usr/bin/true"])
            .arg("--destination")
            .arg(&service_path)
            .output()
            .expect("install service definition");
        assert!(
            service.status.success(),
            "service installation failed: {}",
            String::from_utf8_lossy(&service.stderr)
        );
        let response: Value =
            serde_json::from_slice(&service.stdout).expect("service response JSON");
        let paths = response["readWritePaths"]
            .as_array()
            .expect("service write paths");
        let home_text = home
            .path()
            .canonicalize()
            .expect("canonical home")
            .display()
            .to_string();
        let workspace_text = workspace
            .path()
            .canonicalize()
            .expect("canonical workspace")
            .display()
            .to_string();
        assert!(
            paths
                .iter()
                .any(|path| path.as_str() == Some(home_text.as_str()))
        );
        assert!(
            paths
                .iter()
                .any(|path| path.as_str() == Some(workspace_text.as_str()))
        );
        let unit = fs::read_to_string(service_path).expect("service unit");
        assert!(unit.contains(&format!(
            "ExecStart=\"/usr/bin/true\" --home \"{home_text}\""
        )));
        assert!(!unit.contains(&workspace_text));
        assert!(!unit.contains("ExecStart=/usr/bin/bwrap"));
    }

    let write_disabled = workspace_config(
        home.path(),
        "workspace-write-disable",
        "project",
        None,
        true,
    );
    assert!(write_disabled.status.success());
    let response: Value =
        serde_json::from_slice(&write_disabled.stdout).expect("write disable response");
    assert_eq!(response["operation"], "write_disabled");
    let read_only_again: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("write-disabled workspace"),
    )
    .expect("write-disabled JSON");
    assert!(
        read_only_again["workspaceRoots"][0]
            .get("writable")
            .is_none()
    );

    let duplicate = workspace_config(
        home.path(),
        "workspace-grant",
        "project",
        Some(workspace.path()),
        true,
    );
    assert!(!duplicate.status.success());
    let missing = workspace_config(home.path(), "workspace-revoke", "missing", None, true);
    assert!(!missing.status.success());

    let revoked = workspace_config(home.path(), "workspace-revoke", "project", None, true);
    assert!(
        revoked.status.success(),
        "workspace revoke failed: {}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    let revoke_response: Value =
        serde_json::from_slice(&revoked.stdout).expect("workspace revoke response");
    assert_eq!(revoke_response["operation"], "revoked");
    assert!(revoke_response["canonicalRoot"].is_null());
    let final_config: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("revoked workspace"),
    )
    .expect("revoked JSON");
    assert!(final_config.get("workspaceRoots").is_none());
}

#[cfg(target_os = "linux")]
#[test]
#[allow(clippy::too_many_lines)]
fn config_process_grant_is_pinned_explicit_and_reversible() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    let workspace = tempfile::tempdir().expect("workspace");
    fs::create_dir(home.path().join("config-history")).expect("configuration history");
    fs::write(
        home.path().join("config.json"),
        serde_json::to_vec_pretty(&default_config()).expect("encode default config"),
    )
    .expect("write default config");
    assert!(
        workspace_config(
            home.path(),
            "workspace-grant",
            "project",
            Some(workspace.path()),
            true,
        )
        .status
        .success()
    );
    assert!(
        workspace_config(home.path(), "workspace-write-enable", "project", None, true,)
            .status
            .success()
    );

    let executable = Path::new("/usr/bin/mkdir")
        .canonicalize()
        .expect("canonical test executable");
    let expected_digest = sha256_digest(&fs::read(&executable).expect("read test executable"));
    let unapproved = process_config(
        home.path(),
        "process-grant",
        "mkdir",
        Some(&executable),
        false,
    );
    assert!(!unapproved.status.success());
    let unchanged: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("unchanged config"),
    )
    .expect("unchanged JSON");
    assert!(unchanged.get("commandTools").is_none());

    let user_owned_executable = home.path().join("user-owned-mkdir");
    fs::copy(&executable, &user_owned_executable).expect("copy user-owned executable fixture");
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&user_owned_executable, fs::Permissions::from_mode(0o777))
            .expect("make executable fixture untrusted");
    }
    let untrusted = process_config(
        home.path(),
        "process-grant",
        "untrusted",
        Some(&user_owned_executable),
        true,
    );
    assert!(!untrusted.status.success());
    let unchanged: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("unchanged config"),
    )
    .expect("unchanged JSON");
    assert!(unchanged.get("commandTools").is_none());

    let granted = process_config(
        home.path(),
        "process-grant",
        "mkdir",
        Some(&executable),
        true,
    );
    assert!(
        granted.status.success(),
        "process grant failed: {}",
        String::from_utf8_lossy(&granted.stderr)
    );
    let response: Value = serde_json::from_slice(&granted.stdout).expect("process grant response");
    assert_eq!(response["commandId"], "mkdir");
    assert_eq!(response["executableDigest"], expected_digest);
    assert_eq!(response["operation"], "granted");
    assert_eq!(response["restartRequired"], true);
    assert!(
        Path::new(
            response["replacedConfigurationCopy"]
                .as_str()
                .expect("history path")
        )
        .is_file()
    );
    let configured: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("configured command"),
    )
    .expect("configured JSON");
    assert_eq!(configured["commandTools"][0]["commandId"], "mkdir");
    assert_eq!(
        configured["commandTools"][0]["executable"],
        executable.display().to_string()
    );
    assert_eq!(
        configured["commandTools"][0]["executableDigest"],
        expected_digest
    );

    let duplicate = process_config(
        home.path(),
        "process-grant",
        "mkdir",
        Some(&executable),
        true,
    );
    assert!(!duplicate.status.success());
    let missing = process_config(home.path(), "process-revoke", "missing", None, true);
    assert!(!missing.status.success());
    let unapproved_revoke = process_config(home.path(), "process-revoke", "mkdir", None, false);
    assert!(!unapproved_revoke.status.success());

    let revoked = process_config(home.path(), "process-revoke", "mkdir", None, true);
    assert!(
        revoked.status.success(),
        "process revoke failed: {}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    let response: Value = serde_json::from_slice(&revoked.stdout).expect("process revoke response");
    assert_eq!(response["operation"], "revoked");
    assert!(response["executableDigest"].is_null());
    let final_config: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("revoked process config"),
    )
    .expect("revoked JSON");
    assert!(final_config.get("commandTools").is_none());
}

#[test]
fn config_web_access_brokers_search_secret_and_disables_without_destroying_rollback_material() {
    let home = tempfile::tempdir().expect("temporary Mealy home");
    fs::create_dir(home.path().join("config-history")).expect("configuration history");
    fs::write(
        home.path().join("config.json"),
        serde_json::to_vec_pretty(&default_config()).expect("encode default config"),
    )
    .expect("write default config");

    let unapproved = web_enable(home.path(), false);
    assert!(!unapproved.status.success());
    let enabled = web_enable(home.path(), true);
    assert!(
        enabled.status.success(),
        "web enable failed: {}",
        String::from_utf8_lossy(&enabled.stderr)
    );
    assert!(
        !enabled
            .stdout
            .windows(17)
            .any(|window| window == b"web-search-secret")
    );
    let response: Value = serde_json::from_slice(&enabled.stdout).expect("web response");
    assert_eq!(response["operation"], "enabled");
    assert_eq!(response["searchEnabled"], true);
    assert_eq!(response["secretId"], "test-web-search");
    let config: Value =
        serde_json::from_slice(&fs::read(home.path().join("config.json")).expect("web config"))
            .expect("web JSON");
    assert_eq!(config["webAccess"]["enabled"], true);
    assert_eq!(
        config["webAccess"]["allowedOrigins"][0],
        "http://127.0.0.1:18080"
    );
    assert_eq!(
        config["webAccess"]["search"]["credential"]["secretId"],
        "test-web-search"
    );
    assert!(!config.to_string().contains("web-search-secret"));
    let secret_path = home.path().join("provider-secrets/test-web-search.key");
    assert_eq!(
        fs::read(&secret_path).expect("search secret"),
        b"web-search-secret"
    );

    let disabled = Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home.path())
        .args(["config", "web-disable", "--approve"])
        .output()
        .expect("disable web access");
    assert!(
        disabled.status.success(),
        "web disable failed: {}",
        String::from_utf8_lossy(&disabled.stderr)
    );
    let response: Value = serde_json::from_slice(&disabled.stdout).expect("disable response");
    assert_eq!(response["credentialRetainedOnDisable"], true);
    let config: Value = serde_json::from_slice(
        &fs::read(home.path().join("config.json")).expect("disabled config"),
    )
    .expect("disabled JSON");
    assert!(config.get("webAccess").is_none());
    assert_eq!(
        fs::read(secret_path).expect("retained search secret"),
        b"web-search-secret"
    );
}

fn web_enable(home: &Path, approve: bool) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mealyctl"));
    command
        .arg("--home")
        .arg(home)
        .args([
            "config",
            "web-enable",
            "--allow-origin",
            "http://127.0.0.1:18080",
            "--brave-secret-id",
            "test-web-search",
            "--brave-credential-env",
            "MEALY_TEST_WEB_SEARCH_CREDENTIAL",
            "--brave-base-url",
            "http://127.0.0.1:18080/search",
        ])
        .env("MEALY_TEST_WEB_SEARCH_CREDENTIAL", "web-search-secret");
    if approve {
        command.arg("--approve");
    }
    command.output().expect("enable web access")
}

fn workspace_config(
    home: &Path,
    operation: &str,
    workspace_id: &str,
    root: Option<&Path>,
    approve: bool,
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mealyctl"));
    command
        .arg("--home")
        .arg(home)
        .args(["config", operation, workspace_id]);
    if let Some(root) = root {
        command.arg(root);
    }
    if approve {
        command.arg("--approve");
    }
    command.output().expect("run workspace configuration")
}

fn process_config(
    home: &Path,
    operation: &str,
    command_id: &str,
    executable: Option<&Path>,
    approve: bool,
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mealyctl"));
    command
        .arg("--home")
        .arg(home)
        .args(["config", operation, command_id]);
    if let Some(executable) = executable {
        command.arg(executable);
    }
    if approve {
        command.arg("--approve");
    }
    command.output().expect("run process configuration")
}

fn configure_fallback(home: &Path, credential: &str, residency: &str) -> std::process::Output {
    let secret_id = if residency == "trusted-test" {
        "test-fallback"
    } else {
        "test-fallback-2"
    };
    Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home)
        .args([
            "config",
            "provider-fallback",
            "--provider-id",
            if residency == "trusted-test" {
                "test-fallback.responses"
            } else {
                "test-weaker.responses"
            },
            "--base-url",
            "https://fallback.example.test/v1",
            "--model",
            "test-fallback-model",
            "--secret-id",
            secret_id,
            "--credential-env",
            "MEALY_TEST_PROVIDER_FALLBACK_CREDENTIAL",
            "--residency",
            residency,
            "--context-tokens",
            "32768",
            "--maximum-output-tokens",
            "4096",
            "--input-microunits-per-million-tokens",
            "1000000",
            "--output-microunits-per-million-tokens",
            "2000000",
            "--estimated-latency-ms",
            "1000",
            "--skip-connectivity-test",
            "--approve",
        ])
        .env("MEALY_TEST_PROVIDER_FALLBACK_CREDENTIAL", credential)
        .output()
        .expect("run mealyctl fallback configuration")
}

fn configure_anthropic_fallback(home: &Path, credential: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home)
        .args([
            "config",
            "provider-fallback-anthropic",
            "--provider-id",
            "test-fallback.anthropic",
            "--base-url",
            "https://api.anthropic.example/v1",
            "--model",
            "test-claude-model",
            "--secret-id",
            "test-anthropic-fallback",
            "--credential-env",
            "MEALY_TEST_ANTHROPIC_FALLBACK_CREDENTIAL",
            "--residency",
            "trusted-test",
            "--context-tokens",
            "32768",
            "--maximum-output-tokens",
            "4096",
            "--input-microunits-per-million-tokens",
            "1000000",
            "--output-microunits-per-million-tokens",
            "2000000",
            "--estimated-latency-ms",
            "1000",
            "--skip-connectivity-test",
            "--approve",
        ])
        .env("MEALY_TEST_ANTHROPIC_FALLBACK_CREDENTIAL", credential)
        .output()
        .expect("run mealyctl Anthropic fallback configuration")
}

fn remove_fallback(home: &Path, provider_id: &str, approve: bool) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mealyctl"));
    command
        .arg("--home")
        .arg(home)
        .args(["config", "provider-fallback-remove", provider_id]);
    if approve {
        command.arg("--approve");
    }
    command.output().expect("run fallback removal")
}

fn configure(home: &Path, credential: &str) -> std::process::Output {
    configure_with_secret_id(home, credential, "test-primary")
}

fn configure_with_secret_id(
    home: &Path,
    credential: &str,
    secret_id: &str,
) -> std::process::Output {
    configure_primary(home, credential, secret_id, "trusted-test")
}

fn configure_primary(
    home: &Path,
    credential: &str,
    secret_id: &str,
    residency: &str,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home)
        .args([
            "config",
            "provider",
            "--provider-id",
            "test.responses",
            "--base-url",
            "https://provider.example.test/v1",
            "--model",
            "test-model",
            "--secret-id",
            secret_id,
            "--credential-env",
            "MEALY_TEST_PROVIDER_CREDENTIAL",
            "--residency",
            residency,
            "--context-tokens",
            "32768",
            "--maximum-output-tokens",
            "4096",
            "--input-microunits-per-million-tokens",
            "1000000",
            "--output-microunits-per-million-tokens",
            "2000000",
            "--estimated-latency-ms",
            "1000",
            "--skip-connectivity-test",
            "--approve",
        ])
        .env("MEALY_TEST_PROVIDER_CREDENTIAL", credential)
        .output()
        .expect("run mealyctl provider configuration")
}

fn configure_live(home: &Path, base_url: &str, credential: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home)
        .args([
            "config",
            "provider",
            "--provider-id",
            "test.responses",
            "--base-url",
            base_url,
            "--model",
            "test-model",
            "--secret-id",
            "test-primary",
            "--credential-env",
            "MEALY_TEST_PROVIDER_CREDENTIAL",
            "--residency",
            "local-test",
            "--context-tokens",
            "32768",
            "--maximum-output-tokens",
            "4096",
            "--input-microunits-per-million-tokens",
            "1000000",
            "--output-microunits-per-million-tokens",
            "2000000",
            "--estimated-latency-ms",
            "1000",
            "--approve",
        ])
        .env("MEALY_TEST_PROVIDER_CREDENTIAL", credential)
        .output()
        .expect("run live provider configuration")
}

fn configure_openrouter_live(
    home: &Path,
    base_url: &str,
    credential: &str,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home)
        .args([
            "config",
            "provider-openrouter",
            "--provider-id",
            "test.openrouter.responses",
            "--base-url",
            base_url,
            "--model",
            "anthropic/claude-test",
            "--secret-id",
            "openrouter-primary",
            "--credential-env",
            "MEALY_TEST_OPENROUTER_CREDENTIAL",
            "--residency",
            "openrouter-test",
            "--context-tokens",
            "200000",
            "--maximum-output-tokens",
            "64000",
            "--input-microunits-per-million-tokens",
            "3000000",
            "--output-microunits-per-million-tokens",
            "15000000",
            "--estimated-latency-ms",
            "1000",
            "--approve",
        ])
        .env("MEALY_TEST_OPENROUTER_CREDENTIAL", credential)
        .output()
        .expect("run OpenRouter provider configuration")
}

fn configure_local(home: &Path, base_url: &str, skip_probe: bool) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mealyctl"));
    command.arg("--home").arg(home).args([
        "config",
        "provider-local",
        "--base-url",
        base_url,
        "--model",
        "local-model",
        "--context-tokens",
        "32768",
        "--maximum-output-tokens",
        "4096",
        "--approve",
    ]);
    if skip_probe {
        command.arg("--skip-connectivity-test");
    }
    command.output().expect("run local provider configuration")
}

fn configure_anthropic_live(home: &Path, base_url: &str, credential: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_mealyctl"))
        .arg("--home")
        .arg(home)
        .args([
            "config",
            "provider-anthropic",
            "--provider-id",
            "test.anthropic",
            "--base-url",
            base_url,
            "--model",
            "test-claude-model",
            "--secret-id",
            "anthropic-primary",
            "--credential-env",
            "MEALY_TEST_ANTHROPIC_CREDENTIAL",
            "--residency",
            "local-test",
            "--context-tokens",
            "32768",
            "--maximum-output-tokens",
            "4096",
            "--input-microunits-per-million-tokens",
            "1000000",
            "--output-microunits-per-million-tokens",
            "2000000",
            "--estimated-latency-ms",
            "1000",
            "--approve",
        ])
        .env("MEALY_TEST_ANTHROPIC_CREDENTIAL", credential)
        .output()
        .expect("run live Anthropic provider configuration")
}

fn revoke_provider_secret(home: &Path, secret_id: &str, approve: bool) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mealyctl"));
    command
        .arg("--home")
        .arg(home)
        .args(["config", "provider-secret-revoke", secret_id]);
    if approve {
        command.arg("--approve");
    }
    command.output().expect("run provider secret revocation")
}

fn serve_model_list(
    status: &str,
    response_body: &str,
) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind model discovery server");
    let address = listener.local_addr().expect("model discovery address");
    let status = status.to_owned();
    let response_body = response_body.to_owned();
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept model discovery request");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("model discovery read timeout");
        let mut raw = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let read = stream
                .read(&mut chunk)
                .expect("read model discovery request");
            assert!(read != 0, "model discovery request ended before headers");
            raw.extend_from_slice(&chunk[..read]);
            if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let headers = String::from_utf8(raw).expect("model discovery headers");
        sender
            .send(headers)
            .expect("capture model discovery request");
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
            response_body.len()
        )
        .expect("write model discovery response");
    });
    (format!("http://{address}/v1"), receiver, handle)
}

fn serve_probe(
    status: &str,
    content_type: &str,
    response_body: String,
) -> (
    String,
    mpsc::Receiver<(String, Value)>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind provider probe");
    let address = listener.local_addr().expect("provider probe address");
    let status = status.to_owned();
    let content_type = content_type.to_owned();
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept provider probe");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("probe read timeout");
        let mut raw = Vec::new();
        let mut chunk = [0_u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut chunk).expect("read probe request");
            assert!(read != 0, "probe request ended before headers");
            raw.extend_from_slice(&chunk[..read]);
            if let Some(index) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let headers = String::from_utf8(raw[..header_end].to_vec()).expect("probe headers");
        let length = headers
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("content length"))
                })
            })
            .expect("probe content length");
        while raw.len().saturating_sub(header_end) < length {
            let read = stream.read(&mut chunk).expect("read probe body");
            assert!(read != 0, "probe body ended early");
            raw.extend_from_slice(&chunk[..read]);
        }
        let body = serde_json::from_slice::<Value>(&raw[header_end..header_end + length])
            .expect("probe JSON");
        sender
            .send((headers, body))
            .expect("capture provider probe");
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
            response_body.len()
        )
        .expect("write provider probe response");
    });
    (format!("http://{address}/v1"), receiver, handle)
}

type CapturedHttpRequest = (String, Option<Value>);

fn serve_openrouter_onboarding(
    catalog_body: String,
    probe_body: String,
) -> (
    String,
    mpsc::Receiver<Vec<CapturedHttpRequest>>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind onboarding server");
    let address = listener.local_addr().expect("onboarding server address");
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut captured = Vec::new();
        for (index, response_body) in [catalog_body, probe_body].into_iter().enumerate() {
            let (mut stream, _) = listener.accept().expect("accept onboarding request");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("onboarding read timeout");
            let mut raw = Vec::new();
            let mut chunk = [0_u8; 4096];
            let header_end = loop {
                let read = stream.read(&mut chunk).expect("read onboarding request");
                assert!(read != 0, "onboarding request ended before headers");
                raw.extend_from_slice(&chunk[..read]);
                if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                    break position + 4;
                }
            };
            let headers =
                String::from_utf8(raw[..header_end].to_vec()).expect("onboarding headers");
            let length = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("content length"))
                    })
                })
                .unwrap_or_default();
            while raw.len().saturating_sub(header_end) < length {
                let read = stream.read(&mut chunk).expect("read onboarding body");
                assert!(read != 0, "onboarding body ended early");
                raw.extend_from_slice(&chunk[..read]);
            }
            let body = (length != 0).then(|| {
                serde_json::from_slice::<Value>(&raw[header_end..header_end + length])
                    .expect("onboarding request JSON")
            });
            captured.push((headers, body));
            let content_type = if index == 0 {
                "application/json"
            } else {
                "text/event-stream"
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                response_body.len()
            )
            .expect("write onboarding response");
        }
        sender.send(captured).expect("capture onboarding requests");
    });
    (format!("http://{address}/v1"), receiver, handle)
}

fn default_config() -> Value {
    json!({
        "formatVersion": 1,
        "drainDeadlineMs": 10_000,
        "maximumPendingInputsPerSession": 1_024,
        "agentLoopLimits": {
            "maximumModelCalls": 4,
            "maximumToolCalls": 2,
            "maximumRetries": 1,
            "maximumDelegatedRuns": 2,
            "maximumInputTokens": 32_768,
            "maximumOutputTokens": 4_096,
            "maximumCostMicrounits": 1_000_000,
            "maximumOutputBytes": 4_194_304,
            "maximumWallTimeMs": 120_000,
            "providerTimeoutMs": 5_000,
            "toolTimeoutMs": 5_000,
            "inlineOutputBytes": 1_024,
            "maximumArtifactBytes": 4_194_304
        },
        "concurrencyLimits": {
            "daemonAgentRuns": 1,
            "principalAgentRuns": 1,
            "sessionAgentRuns": 1,
            "providerRequests": 1,
            "providerRequestsPerMinute": 600,
            "extensionInvocations": 1,
            "agentRoleRuns": 1,
            "resourceClassInvocations": 1
        },
        "provider": {"kind": "builtin_fixture"},
        "artifactGcMinimumAgeHours": 24,
        "forensicBackupOnOpenFailure": true,
        "retentionPolicy": {
            "dataClassMinimumAgeHours": {
                "canonical_audit": 87_600,
                "temporary_artifact": 24,
                "unreferenced_artifact": 24
            },
            "sensitivityMinimumAgeHours": {
                "internal": 720,
                "private": 8_760,
                "public": 24,
                "restricted": 87_600
            },
            "protectedPrincipalIds": [],
            "protectedTaskIds": [],
            "protectedChannelBindingIds": [],
            "legalHoldLabels": []
        }
    })
}
