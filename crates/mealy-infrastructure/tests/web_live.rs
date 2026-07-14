//! Opt-in public-network proof for the production bounded web fetch adapter.

use mealy_application::{
    CancellationProbe, ProviderCredentialReference, ReadOnlyTool, WebAccessConfig, WebSearchConfig,
    is_sha256_digest,
};
use mealy_infrastructure::WebReadTool;
use serde_json::{Value, json};
use zeroize::Zeroizing;

struct NeverCancelled;

impl CancellationProbe for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

#[test]
#[ignore = "opt-in public HTTPS check; requires direct DNS and network access"]
fn public_https_fetch_is_pinned_bounded_sanitized_and_cited() {
    let config = WebAccessConfig {
        enabled: true,
        allow_public_internet: false,
        allowed_domains: vec!["example.com".to_owned()],
        allowed_origins: Vec::new(),
        search: None,
    };
    let mut tools = WebReadTool::suite(config, None).expect("bounded fetch tool");
    assert_eq!(tools.len(), 1);
    let tool = tools.pop().expect("fetch tool");
    assert_eq!(tool.descriptor().tool_id, "web.fetch");
    let output = tool
        .execute(
            &json!({"url": "https://example.com/", "maximumBytes": 32768}),
            &NeverCancelled,
        )
        .expect("live public fetch");
    assert_eq!(output.media_type, "application/json");
    assert_eq!(output.source_locator, "https://example.com/");
    let body: Value = serde_json::from_slice(&output.bytes).expect("bounded JSON output");
    assert_eq!(body["status"], 200);
    assert_eq!(body["mediaType"], "text/html");
    assert_eq!(body["sourceLocator"], "https://example.com/");
    assert_eq!(body["url"], "https://example.com/");
    assert!(
        body["content"]
            .as_str()
            .is_some_and(|content| content.contains("Example Domain"))
    );
    assert!(body["contentSha256"].as_str().is_some_and(is_sha256_digest));
    assert_eq!(tool.invocation_count(), 1);
}

#[test]
#[ignore = "opt-in live Brave Search check; requires BRAVE_SEARCH_API_KEY and public network"]
fn live_brave_search_is_credential_scoped_bounded_and_cited() {
    let credential = Zeroizing::new(
        std::env::var("BRAVE_SEARCH_API_KEY")
            .expect("BRAVE_SEARCH_API_KEY must be set for the opt-in check"),
    );
    let config = WebAccessConfig {
        enabled: true,
        allow_public_internet: true,
        allowed_domains: Vec::new(),
        allowed_origins: Vec::new(),
        search: Some(WebSearchConfig::Brave {
            base_url: "https://api.search.brave.com/res/v1/web/search".to_owned(),
            credential: ProviderCredentialReference::Broker {
                secret_id: "live-brave-search-smoke".to_owned(),
            },
        }),
    };
    let tools = WebReadTool::suite(config, Some(credential)).expect("bounded live web tools");
    let search = tools
        .iter()
        .find(|tool| tool.descriptor().tool_id == "web.search")
        .expect("search tool");
    let output = search
        .execute(
            &json!({"query": "OpenAI", "maximumResults": 3}),
            &NeverCancelled,
        )
        .expect("live Brave Search");
    assert_eq!(output.media_type, "application/json");
    assert!(output.source_locator.starts_with("search://brave/"));
    let body: Value = serde_json::from_slice(&output.bytes).expect("bounded search JSON");
    assert_eq!(body["query"], "OpenAI");
    assert_eq!(body["sourceLocator"], output.source_locator);
    let results = body["results"].as_array().expect("search result array");
    assert!(!results.is_empty() && results.len() <= 3);
    assert!(results.iter().all(|result| {
        let Some(url) = result["url"].as_str() else {
            return false;
        };
        result["sourceLocator"].as_str() == Some(url)
            && url.starts_with("https://")
            && result["title"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
            && result["description"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
    }));
    assert_eq!(search.invocation_count(), 1);
}
