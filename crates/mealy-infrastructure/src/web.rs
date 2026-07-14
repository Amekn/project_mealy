use mealy_application::{
    CancellationProbe, ReadOnlyTool, ReadToolDescriptor, ReadToolError, ReadToolOutput,
    WebAccessConfig, WebSearchConfig, sha256_digest, web_url_authorized_by_capabilities,
};
use reqwest::{
    StatusCode,
    blocking::{Client, Response},
    header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, USER_AGENT},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

const MAXIMUM_FETCH_BYTES: usize = 128 * 1024;
const DEFAULT_FETCH_BYTES: usize = 64 * 1024;
const MAXIMUM_SEARCH_RESPONSE_BYTES: usize = 512 * 1024;
const MAXIMUM_SEARCH_RESULTS: usize = 20;
const DEFAULT_SEARCH_RESULTS: usize = 8;
const MAXIMUM_TOOL_OUTPUT_BYTES: u64 = 1024 * 1024;
const MAXIMUM_QUERY_BYTES: usize = 512;
const NETWORK_TIMEOUT: Duration = Duration::from_secs(8);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Invalid or unenforceable web-tool configuration.
#[derive(Debug, Error)]
pub enum WebToolConfigurationError {
    /// Non-secret authority configuration is malformed or disabled.
    #[error("web tool configuration is invalid")]
    Invalid,
    /// Search was configured without its startup-resolved credential.
    #[error("web search credential is unavailable")]
    MissingCredential,
    /// A canonical descriptor could not be constructed.
    #[error("web tool descriptor is invalid")]
    InvalidDescriptor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WebOperation {
    Fetch,
    Search,
}

impl WebOperation {
    const fn tool_id(self) -> &'static str {
        match self {
            Self::Fetch => "web.fetch",
            Self::Search => "web.search",
        }
    }

    fn from_tool_id(value: &str) -> Option<Self> {
        match value {
            "web.fetch" => Some(Self::Fetch),
            "web.search" => Some(Self::Search),
            _ => None,
        }
    }
}

/// One bounded network read operation with explicit destination authority.
pub struct WebReadTool {
    operation: WebOperation,
    descriptor: ReadToolDescriptor,
    config: Arc<WebAccessConfig>,
    search_credential: Option<Arc<Zeroizing<String>>>,
    invocation_count: AtomicUsize,
}

impl std::fmt::Debug for WebReadTool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WebReadTool")
            .field("operation", &self.operation)
            .field("descriptor", &self.descriptor)
            .field("config", &self.config)
            .field("credential_configured", &self.search_credential.is_some())
            .field("invocation_count", &self.invocation_count())
            .finish()
    }
}

impl WebReadTool {
    /// Builds fetch and optionally search tools from exact activated authority.
    ///
    /// # Errors
    ///
    /// Returns a configuration error for invalid authority, missing search credentials, or a
    /// descriptor construction failure.
    pub fn suite(
        config: WebAccessConfig,
        search_credential: Option<Zeroizing<String>>,
    ) -> Result<Vec<Self>, WebToolConfigurationError> {
        config
            .validate()
            .map_err(|_| WebToolConfigurationError::Invalid)?;
        if !config.enabled {
            return Err(WebToolConfigurationError::Invalid);
        }
        if config.search.is_some() != search_credential.is_some() {
            return Err(WebToolConfigurationError::MissingCredential);
        }
        let config = Arc::new(config);
        let search_credential = search_credential.map(Arc::new);
        let mut tools = Vec::new();
        if config.allow_public_internet
            || !config.allowed_domains.is_empty()
            || !config.allowed_origins.is_empty()
        {
            tools.push(Self {
                operation: WebOperation::Fetch,
                descriptor: web_descriptor(WebOperation::Fetch)?,
                config: Arc::clone(&config),
                search_credential: None,
                invocation_count: AtomicUsize::new(0),
            });
        }
        if config.search.is_some() {
            tools.push(Self {
                operation: WebOperation::Search,
                descriptor: web_descriptor(WebOperation::Search)?,
                config,
                search_credential,
                invocation_count: AtomicUsize::new(0),
            });
        }
        Ok(tools)
    }

    /// Number of invocations reaching this adapter in the current process.
    #[must_use]
    pub fn invocation_count(&self) -> usize {
        self.invocation_count.load(Ordering::SeqCst)
    }
}

impl ReadOnlyTool for WebReadTool {
    fn descriptor(&self) -> ReadToolDescriptor {
        self.descriptor.clone()
    }

    fn validate_arguments(&self, arguments: &Value) -> Result<(), ReadToolError> {
        validate_operation_arguments(self.operation, arguments).map(|_| ())
    }

    fn execute(
        &self,
        arguments: &Value,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ReadToolOutput, ReadToolError> {
        self.invocation_count.fetch_add(1, Ordering::SeqCst);
        let source_locator = validate_operation_arguments(self.operation, arguments)?;
        if cancellation.is_cancelled() {
            return Err(ReadToolError::Cancelled);
        }
        let output = match self.operation {
            WebOperation::Fetch => execute_fetch(&self.config, arguments, cancellation)?,
            WebOperation::Search => execute_search(
                &self.config,
                self.search_credential
                    .as_deref()
                    .ok_or_else(|| unavailable("web search credential is unavailable"))?,
                arguments,
                cancellation,
            )?,
        };
        let bytes =
            serde_json::to_vec(&output).map_err(|_| unavailable("web output encoding failed"))?;
        let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if actual > self.descriptor.maximum_output_bytes {
            return Err(ReadToolError::OutputTooLarge {
                actual,
                maximum: self.descriptor.maximum_output_bytes,
            });
        }
        Ok(ReadToolOutput {
            media_type: "application/json".to_owned(),
            bytes,
            source_locator,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FetchArguments {
    url: String,
    #[serde(default = "default_fetch_bytes")]
    maximum_bytes: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SearchArguments {
    query: String,
    #[serde(default = "default_search_results")]
    maximum_results: usize,
}

fn default_fetch_bytes() -> usize {
    DEFAULT_FETCH_BYTES
}

fn default_search_results() -> usize {
    DEFAULT_SEARCH_RESULTS
}

fn validate_operation_arguments(
    operation: WebOperation,
    arguments: &Value,
) -> Result<String, ReadToolError> {
    match operation {
        WebOperation::Fetch => {
            let parsed: FetchArguments = parse_arguments(arguments)?;
            if !(1..=MAXIMUM_FETCH_BYTES).contains(&parsed.maximum_bytes) {
                return invalid_arguments("maximumBytes is outside its bound");
            }
            canonical_fetch_url(&parsed.url)
        }
        WebOperation::Search => {
            let parsed: SearchArguments = parse_arguments(arguments)?;
            if parsed.query.is_empty()
                || parsed.query.len() > MAXIMUM_QUERY_BYTES
                || parsed.query.trim() != parsed.query
                || parsed.query.chars().any(char::is_control)
                || !(1..=MAXIMUM_SEARCH_RESULTS).contains(&parsed.maximum_results)
            {
                return invalid_arguments("query or maximumResults is invalid");
            }
            Ok(format!(
                "search://brave/{}",
                sha256_digest(parsed.query.as_bytes())
            ))
        }
    }
}

/// Validates recorded arguments and derives their logical source locator without live network use.
pub(crate) fn validate_web_tool_arguments(
    tool_id: &str,
    arguments: &Value,
) -> Result<String, ReadToolError> {
    let operation = WebOperation::from_tool_id(tool_id)
        .ok_or_else(|| ReadToolError::InvalidArguments("unknown web tool".to_owned()))?;
    validate_operation_arguments(operation, arguments)
}

fn canonical_fetch_url(value: &str) -> Result<String, ReadToolError> {
    if value.is_empty() || value.len() > 4_096 || value.trim() != value {
        return invalid_arguments("url is invalid");
    }
    let url = Url::parse(value).map_err(|_| invalid_arguments_error("url is invalid"))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
        || !matches!(url.scheme(), "http" | "https")
    {
        return invalid_arguments("url is invalid");
    }
    Ok(url.to_string())
}

fn parse_arguments<T: for<'de> Deserialize<'de>>(arguments: &Value) -> Result<T, ReadToolError> {
    serde_json::from_value(arguments.clone())
        .map_err(|_| invalid_arguments_error("arguments do not match schema"))
}

fn invalid_arguments<T>(message: &str) -> Result<T, ReadToolError> {
    Err(invalid_arguments_error(message))
}

fn invalid_arguments_error(message: &str) -> ReadToolError {
    ReadToolError::InvalidArguments(message.to_owned())
}

fn unavailable(message: &str) -> ReadToolError {
    ReadToolError::Unavailable(message.to_owned())
}

fn execute_fetch(
    config: &WebAccessConfig,
    arguments: &Value,
    cancellation: &dyn CancellationProbe,
) -> Result<Value, ReadToolError> {
    let parsed: FetchArguments = parse_arguments(arguments)?;
    let url = Url::parse(&canonical_fetch_url(&parsed.url)?)
        .map_err(|_| invalid_arguments_error("url is invalid"))?;
    let destinations = config.capability_network_destinations();
    if !web_url_authorized_by_capabilities(url.as_str(), &destinations) {
        return invalid_arguments("url is outside configured web authority");
    }
    let (client, allowed_addresses) = build_pinned_client(&url, false, config)?;
    let response = client
        .get(url.clone())
        .header(USER_AGENT, "Mealy/0.1 bounded-web-fetch")
        .header(
            ACCEPT,
            "text/plain, text/html, application/json, application/xhtml+xml",
        )
        .send()
        .map_err(|_| unavailable("web fetch transport failed"))?;
    let (status, media_type, bytes) = read_response(
        response,
        &allowed_addresses,
        parsed.maximum_bytes,
        cancellation,
    )?;
    let raw_digest = sha256_digest(&bytes);
    let text = String::from_utf8(bytes)
        .map_err(|_| invalid_arguments_error("web fetch response is not UTF-8 text"))?;
    let content = if matches!(media_type.as_str(), "text/html" | "application/xhtml+xml") {
        html_to_text(&text)
    } else {
        text
    };
    Ok(json!({
        "content": content,
        "contentSha256": raw_digest,
        "mediaType": media_type,
        "sourceLocator": url.as_str(),
        "status": status.as_u16(),
        "url": url.as_str(),
    }))
}

fn execute_search(
    config: &WebAccessConfig,
    credential: &str,
    arguments: &Value,
    cancellation: &dyn CancellationProbe,
) -> Result<Value, ReadToolError> {
    let parsed: SearchArguments = parse_arguments(arguments)?;
    let search = config
        .search
        .as_ref()
        .ok_or_else(|| unavailable("web search is not configured"))?;
    let endpoint =
        Url::parse(search.base_url()).map_err(|_| unavailable("web search endpoint is invalid"))?;
    let (client, allowed_addresses) = build_pinned_client(&endpoint, true, config)?;
    let maximum_results = parsed.maximum_results.to_string();
    let response = match search {
        WebSearchConfig::Brave { .. } => client
            .get(endpoint)
            .header(USER_AGENT, "Mealy/0.1 bounded-web-search")
            .header(ACCEPT, "application/json")
            .header("X-Subscription-Token", credential)
            .query(&[
                ("q", parsed.query.as_str()),
                ("count", maximum_results.as_str()),
                ("safesearch", "moderate"),
            ])
            .send()
            .map_err(|_| unavailable("web search transport failed"))?,
    };
    let (_, media_type, bytes) = read_response(
        response,
        &allowed_addresses,
        MAXIMUM_SEARCH_RESPONSE_BYTES,
        cancellation,
    )?;
    if media_type != "application/json" {
        return Err(unavailable(
            "web search returned an unsupported content type",
        ));
    }
    let body: Value = serde_json::from_slice(&bytes)
        .map_err(|_| unavailable("web search returned invalid JSON"))?;
    let raw_results = body
        .get("web")
        .and_then(|web| web.get("results"))
        .and_then(Value::as_array)
        .ok_or_else(|| unavailable("web search response omitted results"))?;
    let destinations = config.capability_network_destinations();
    let mut results = Vec::new();
    for result in raw_results {
        if results.len() >= parsed.maximum_results {
            break;
        }
        let (Some(title), Some(url), Some(description)) = (
            result.get("title").and_then(Value::as_str),
            result.get("url").and_then(Value::as_str),
            result.get("description").and_then(Value::as_str),
        ) else {
            continue;
        };
        let Ok(canonical_url) = canonical_fetch_url(url) else {
            continue;
        };
        if title.len() > 1_024
            || description.len() > 4_096
            || !web_url_authorized_by_capabilities(&canonical_url, &destinations)
        {
            continue;
        }
        results.push(json!({
            "description": description,
            "sourceLocator": canonical_url,
            "title": title,
            "url": canonical_url,
        }));
    }
    let source_locator = format!("search://brave/{}", sha256_digest(parsed.query.as_bytes()));
    Ok(json!({
        "query": parsed.query,
        "results": results,
        "sourceLocator": source_locator,
        "truncated": raw_results.len() > parsed.maximum_results,
    }))
}

fn build_pinned_client(
    url: &Url,
    search_endpoint: bool,
    config: &WebAccessConfig,
) -> Result<(Client, BTreeSet<IpAddr>), ReadToolError> {
    if search_endpoint
        && config
            .search
            .as_ref()
            .is_none_or(|search| search.base_url() != url.as_str())
    {
        return Err(unavailable("web search endpoint authority mismatch"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| invalid_arguments_error("url host is absent"))?;
    let literal = host.parse::<IpAddr>().ok();
    let sockets = resolve_pinned_web_destination(url, config)?;
    let addresses = sockets.iter().map(SocketAddr::ip).collect();
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(NETWORK_TIMEOUT);
    if literal.is_none() {
        builder = builder.resolve_to_addrs(host, &sockets);
    }
    let client = builder
        .build()
        .map_err(|_| unavailable("bounded web client initialization failed"))?;
    Ok((client, addresses))
}

/// Resolves one already canonical HTTP(S) URL to an exact set of policy-authorized peer sockets.
///
/// This is shared by the direct web adapter and the browser's scoped host proxy. DNS results are
/// rejected as a whole if any address is not globally routed; literal loopback remains available
/// only through an exact owner-granted HTTP origin.
pub(crate) fn resolve_pinned_web_destination(
    url: &Url,
    config: &WebAccessConfig,
) -> Result<Vec<SocketAddr>, ReadToolError> {
    if !web_url_authorized_by_capabilities(url.as_str(), &config.capability_network_destinations())
    {
        return invalid_arguments("url is outside configured web authority");
    }
    let host = url
        .host_str()
        .ok_or_else(|| invalid_arguments_error("url host is absent"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| invalid_arguments_error("url port is invalid"))?;
    let exact_origin = config
        .allowed_origins
        .iter()
        .any(|origin| origin == &url.origin().ascii_serialization());
    let literal = host.parse::<IpAddr>().ok();
    let addresses = if let Some(address) = literal {
        if address.is_loopback() {
            if !exact_origin || url.scheme() != "http" {
                return invalid_arguments(
                    "loopback web access requires an exact HTTP origin grant",
                );
            }
        } else if !is_public_address(address) {
            return invalid_arguments("web destination IP is not globally routable");
        }
        BTreeSet::from([address])
    } else {
        let resolved = (host, port)
            .to_socket_addrs()
            .map_err(|_| unavailable("web destination DNS resolution failed"))?
            .map(|address| address.ip())
            .collect::<BTreeSet<_>>();
        if resolved.is_empty() || resolved.iter().any(|address| !is_public_address(*address)) {
            return invalid_arguments("web destination DNS includes a non-public address");
        }
        resolved
    };
    Ok(addresses
        .into_iter()
        .map(|address| SocketAddr::new(address, port))
        .collect())
}

fn read_response(
    mut response: Response,
    allowed_addresses: &BTreeSet<IpAddr>,
    maximum_bytes: usize,
    cancellation: &dyn CancellationProbe,
) -> Result<(StatusCode, String, Vec<u8>), ReadToolError> {
    if response
        .remote_addr()
        .is_none_or(|address| !allowed_addresses.contains(&address.ip()))
    {
        return Err(unavailable(
            "web peer address did not match pinned resolution",
        ));
    }
    let status = response.status();
    if !status.is_success() {
        return Err(unavailable("web endpoint returned a non-success status"));
    }
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > maximum_bytes)
    {
        return Err(ReadToolError::OutputTooLarge {
            actual: u64::try_from(maximum_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
            maximum: u64::try_from(maximum_bytes).unwrap_or(u64::MAX),
        });
    }
    let media_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .filter(|value| {
            matches!(
                value.as_str(),
                "text/plain" | "text/html" | "application/json" | "application/xhtml+xml"
            )
        })
        .ok_or_else(|| unavailable("web endpoint returned an unsupported content type"))?;
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        if cancellation.is_cancelled() {
            return Err(ReadToolError::Cancelled);
        }
        let read = response
            .read(&mut buffer)
            .map_err(|_| unavailable("web response body failed"))?;
        if read == 0 {
            break;
        }
        if bytes.len().saturating_add(read) > maximum_bytes {
            return Err(ReadToolError::OutputTooLarge {
                actual: u64::try_from(bytes.len().saturating_add(read)).unwrap_or(u64::MAX),
                maximum: u64::try_from(maximum_bytes).unwrap_or(u64::MAX),
            });
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok((status, media_type, bytes))
}

fn is_public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [first, second, third, fourth] = address.octets();
    !(first == 0
        || first == 10
        || first == 127
        || first >= 224
        || first == 100 && (64..=127).contains(&second)
        || first == 169 && second == 254
        || first == 172 && (16..=31).contains(&second)
        || first == 192 && second == 0 && matches!(third, 0 | 2)
        || first == 192 && second == 88 && third == 99
        || first == 192 && second == 168
        || first == 198 && matches!(second, 18 | 19)
        || first == 198 && second == 51 && third == 100
        || first == 203 && second == 0 && third == 113
        || first == 255 && second == 255 && third == 255 && fourth == 255)
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    if !is_allocated_global_unicast_ipv6(address) {
        return false;
    }
    let segments = address.segments();
    let ietf_protocol_assignments = matches_ipv6_prefix(address, 0x2001, 0, 23);
    let globally_reachable_protocol_assignment =
        matches!(segments, [0x2001, 1, 0, 0, 0, 0, 0, 1..=3])
            || matches_ipv6_prefix(address, 0x2001, 3, 32)
            || (segments[0] == 0x2001 && segments[1] == 4 && segments[2] == 0x0112)
            || matches_ipv6_prefix(address, 0x2001, 0x20, 28)
            || matches_ipv6_prefix(address, 0x2001, 0x30, 28);
    let documentation = matches_ipv6_prefix(address, 0x2001, 0x0db8, 32);
    (!ietf_protocol_assignments || globally_reachable_protocol_assignment)
        && !documentation
        && address.to_ipv4_mapped().is_none()
}

// Snapshot of IANA's allocated IPv6 Global Unicast Address Space as updated 2025-10-10.
// Unlisted 2000::/3 space is reserved for future allocation, so web access fails closed until a
// reviewed release updates this table. The separately registered 2002::/16 transition range is
// deliberately absent.
fn is_allocated_global_unicast_ipv6(address: Ipv6Addr) -> bool {
    const ALLOCATED: &[(u16, u16, u32)] = &[
        (0x2001, 0x0000, 23),
        (0x2001, 0x0200, 23),
        (0x2001, 0x0400, 23),
        (0x2001, 0x0600, 23),
        (0x2001, 0x0800, 22),
        (0x2001, 0x0c00, 23),
        (0x2001, 0x0e00, 23),
        (0x2001, 0x1200, 23),
        (0x2001, 0x1400, 22),
        (0x2001, 0x1800, 23),
        (0x2001, 0x1a00, 23),
        (0x2001, 0x1c00, 22),
        (0x2001, 0x2000, 19),
        (0x2001, 0x4000, 23),
        (0x2001, 0x4200, 23),
        (0x2001, 0x4400, 23),
        (0x2001, 0x4600, 23),
        (0x2001, 0x4800, 23),
        (0x2001, 0x4a00, 23),
        (0x2001, 0x4c00, 23),
        (0x2001, 0x5000, 20),
        (0x2001, 0x8000, 19),
        (0x2001, 0xa000, 20),
        (0x2001, 0xb000, 20),
        (0x2003, 0x0000, 18),
        (0x2400, 0x0000, 12),
        (0x2410, 0x0000, 12),
        (0x2600, 0x0000, 12),
        (0x2610, 0x0000, 23),
        (0x2620, 0x0000, 23),
        (0x2630, 0x0000, 12),
        (0x2800, 0x0000, 12),
        (0x2a00, 0x0000, 12),
        (0x2a10, 0x0000, 12),
        (0x2c00, 0x0000, 12),
    ];
    ALLOCATED
        .iter()
        .any(|(first, second, prefix)| matches_ipv6_prefix(address, *first, *second, *prefix))
}

fn matches_ipv6_prefix(address: Ipv6Addr, first: u16, second: u16, prefix: u32) -> bool {
    let address = u128::from(address);
    let network = (u128::from(first) << 112) | (u128::from(second) << 96);
    let mask = u128::MAX << (128_u32.saturating_sub(prefix));
    address & mask == network & mask
}

fn html_to_text(input: &str) -> String {
    let without_active = remove_delimited_blocks(input, "<!--", "-->");
    let without_active = remove_element_blocks(&without_active, "script");
    let without_active = remove_element_blocks(&without_active, "style");
    let without_active = remove_element_blocks(&without_active, "noscript");
    let mut output = String::with_capacity(without_active.len());
    let mut in_tag = false;
    let mut quote = None;
    for character in without_active.chars() {
        if in_tag {
            if let Some(active_quote) = quote {
                if character == active_quote {
                    quote = None;
                }
                continue;
            }
            match character {
                '\'' | '"' => quote = Some(character),
                '>' => in_tag = false,
                _ => {}
            }
            continue;
        }
        if character == '<' {
            in_tag = true;
            quote = None;
            if !output.ends_with(char::is_whitespace) {
                output.push(' ');
            }
        } else {
            output.push(character);
        }
    }
    let decoded = decode_common_html_entities(&output);
    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn remove_element_blocks(input: &str, tag: &str) -> String {
    let lowercase = input.to_ascii_lowercase();
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    while let Some((start, open_end, self_closing)) =
        find_element_tag(input, &lowercase, tag, false, cursor)
    {
        output.push_str(&input[cursor..start]);
        output.push(' ');
        if self_closing {
            cursor = open_end;
            continue;
        }
        let Some((_, close_end, _)) = find_element_tag(input, &lowercase, tag, true, open_end)
        else {
            cursor = input.len();
            break;
        };
        cursor = close_end;
    }
    output.push_str(&input[cursor..]);
    output
}

fn find_element_tag(
    input: &str,
    lowercase: &str,
    tag: &str,
    closing: bool,
    cursor: usize,
) -> Option<(usize, usize, bool)> {
    let marker = if closing {
        format!("</{tag}")
    } else {
        format!("<{tag}")
    };
    let mut search_from = cursor;
    while let Some(relative_start) = lowercase[search_from..].find(&marker) {
        let start = search_from.saturating_add(relative_start);
        let boundary = start.saturating_add(marker.len());
        if lowercase
            .as_bytes()
            .get(boundary)
            .is_some_and(|byte| byte.is_ascii_whitespace() || matches!(byte, b'/' | b'>'))
            || boundary == lowercase.len()
        {
            let Some(end) = find_markup_tag_end(input, boundary) else {
                return Some((start, input.len(), false));
            };
            let self_closing = !closing
                && input[start..end.saturating_sub(1)]
                    .trim_end()
                    .ends_with('/');
            return Some((start, end, self_closing));
        }
        search_from = start.saturating_add(1);
    }
    None
}

fn find_markup_tag_end(input: &str, cursor: usize) -> Option<usize> {
    let mut quote = None;
    for (offset, character) in input[cursor..].char_indices() {
        if let Some(active_quote) = quote {
            if character == active_quote {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '>' => return Some(cursor.saturating_add(offset).saturating_add(1)),
            _ => {}
        }
    }
    None
}

fn remove_delimited_blocks(input: &str, open: &str, close: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    while let Some(relative_start) = input[cursor..].find(open) {
        let start = cursor.saturating_add(relative_start);
        output.push_str(&input[cursor..start]);
        output.push(' ');
        let content_start = start.saturating_add(open.len());
        let Some(relative_end) = input[content_start..].find(close) else {
            cursor = input.len();
            break;
        };
        cursor = content_start
            .saturating_add(relative_end)
            .saturating_add(close.len());
    }
    output.push_str(&input[cursor..]);
    output
}

fn decode_common_html_entities(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    while let Some(relative_start) = input[cursor..].find('&') {
        let start = cursor.saturating_add(relative_start);
        output.push_str(&input[cursor..start]);
        let tail = &input[start.saturating_add(1)..];
        let Some(relative_end) = tail.find(';').filter(|end| *end <= 12) else {
            output.push('&');
            cursor = start.saturating_add(1);
            continue;
        };
        let entity = &tail[..relative_end];
        let decoded = match entity {
            "nbsp" => Some(' '),
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" | "#39" => Some('\''),
            _ => decode_numeric_html_entity(entity),
        };
        if let Some(character) = decoded {
            output.push(character);
            cursor = start.saturating_add(relative_end).saturating_add(2);
        } else {
            output.push('&');
            cursor = start.saturating_add(1);
        }
    }
    output.push_str(&input[cursor..]);
    output
}

fn decode_numeric_html_entity(entity: &str) -> Option<char> {
    let value = if let Some(hexadecimal) = entity
        .strip_prefix("#x")
        .or_else(|| entity.strip_prefix("#X"))
    {
        u32::from_str_radix(hexadecimal, 16).ok()?
    } else {
        entity.strip_prefix('#')?.parse::<u32>().ok()?
    };
    char::from_u32(value)
        .filter(|character| !character.is_control() || matches!(character, '\t' | '\n' | '\r'))
}

fn web_descriptor(
    operation: WebOperation,
) -> Result<ReadToolDescriptor, WebToolConfigurationError> {
    let input_schema = match operation {
        WebOperation::Fetch => json!({
            "type": "object",
            "properties": {
                "url": {"type": "string", "minLength": 1, "maxLength": 4096},
                "maximumBytes": {"type": "integer", "minimum": 1, "maximum": MAXIMUM_FETCH_BYTES}
            },
            "required": ["url"],
            "additionalProperties": false
        }),
        WebOperation::Search => json!({
            "type": "object",
            "properties": {
                "query": {"type": "string", "minLength": 1, "maxLength": MAXIMUM_QUERY_BYTES},
                "maximumResults": {"type": "integer", "minimum": 1, "maximum": MAXIMUM_SEARCH_RESULTS}
            },
            "required": ["query"],
            "additionalProperties": false
        }),
    };
    let mut descriptor = ReadToolDescriptor {
        tool_id: operation.tool_id().to_owned(),
        version: "1".to_owned(),
        schema_digest: sha256_digest(input_schema.to_string().as_bytes()),
        input_schema,
        output_schema: json!({"type": "object"}),
        descriptor_digest: String::new(),
        effect_class: "read_only".to_owned(),
        risk_class: "low".to_owned(),
        required_capability: "network:web".to_owned(),
        timeout: Duration::from_secs(10),
        maximum_output_bytes: MAXIMUM_TOOL_OUTPUT_BYTES,
        conflict_key_template: match operation {
            WebOperation::Fetch => "web.fetch:{url}",
            WebOperation::Search => "web.search:{query}",
        }
        .to_owned(),
        recovery: "retry".to_owned(),
    };
    descriptor.descriptor_digest = descriptor
        .computed_descriptor_digest()
        .map_err(|_| WebToolConfigurationError::InvalidDescriptor)?;
    descriptor
        .validate_evidence()
        .map_err(|_| WebToolConfigurationError::InvalidDescriptor)?;
    Ok(descriptor)
}

#[cfg(test)]
mod tests {
    use super::{WebReadTool, canonical_fetch_url, html_to_text, is_public_address};
    use mealy_application::{
        CancellationProbe, ProviderCredentialReference, ReadOnlyTool, ReadToolError,
        WebAccessConfig, WebSearchConfig,
    };
    use serde_json::{Value, json};
    use std::{
        io::{Read, Write},
        net::{IpAddr, Ipv4Addr, TcpListener},
        thread,
    };
    use zeroize::Zeroizing;

    struct NeverCancelled;

    impl CancellationProbe for NeverCancelled {
        fn is_cancelled(&self) -> bool {
            false
        }
    }

    #[test]
    fn fetch_and_search_are_pinned_bounded_cited_and_secret_safe() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("mock web listener");
        let address = listener.local_addr().expect("mock address");
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept request");
                let mut request = [0_u8; 8192];
                let size = stream.read(&mut request).expect("read request");
                let request = String::from_utf8_lossy(&request[..size]);
                let (content_type, body) = if request.starts_with("GET /search?") {
                    assert!(request.contains("x-subscription-token: search-secret"));
                    (
                        "application/json",
                        json!({
                            "web": {
                                "results": [{
                                    "title": "Result",
                                    "url": format!("http://{address}/page"),
                                    "description": "Evidence"
                                }]
                            }
                        })
                        .to_string(),
                    )
                } else {
                    (
                        "text/html",
                        "<html><style>hidden</style><body>Public <b>evidence</b><script>bad()</script></body></html>".to_owned(),
                    )
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .expect("write response");
            }
        });
        let origin = format!("http://{address}");
        let config = WebAccessConfig {
            enabled: true,
            allow_public_internet: false,
            allowed_domains: Vec::new(),
            allowed_origins: vec![origin.clone()],
            search: Some(WebSearchConfig::Brave {
                base_url: format!("{origin}/search"),
                credential: ProviderCredentialReference::Broker {
                    secret_id: "search".to_owned(),
                },
            }),
        };
        let tools = WebReadTool::suite(config, Some(Zeroizing::new("search-secret".to_owned())))
            .expect("web tools");
        let fetch = tools
            .iter()
            .find(|tool| tool.descriptor().tool_id == "web.fetch")
            .expect("fetch tool")
            .execute(&json!({"url": format!("{origin}/page")}), &NeverCancelled)
            .expect("fetch");
        let fetch: Value = serde_json::from_slice(&fetch.bytes).expect("fetch JSON");
        assert_eq!(fetch["sourceLocator"], format!("{origin}/page"));
        assert_eq!(fetch["content"], "Public evidence");

        let search = tools
            .iter()
            .find(|tool| tool.descriptor().tool_id == "web.search")
            .expect("search tool")
            .execute(&json!({"query": "evidence"}), &NeverCancelled)
            .expect("search");
        let search: Value = serde_json::from_slice(&search.bytes).expect("search JSON");
        assert_eq!(
            search["results"][0]["sourceLocator"],
            format!("{origin}/page")
        );
        assert!(
            search["sourceLocator"]
                .as_str()
                .is_some_and(|locator| locator.starts_with("search://brave/"))
        );
        server.join().expect("mock server");
    }

    #[test]
    fn private_authority_fails_closed() {
        assert!(!is_public_address(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_public_address(IpAddr::V4(Ipv4Addr::new(
            169, 254, 1, 1
        ))));
        assert!(!is_public_address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_public_address(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));

        let config = WebAccessConfig {
            enabled: true,
            allow_public_internet: true,
            ..WebAccessConfig::default()
        };
        let tools = WebReadTool::suite(config, None).expect("fetch tool");
        assert!(matches!(
            tools[0].execute(&json!({"url": "http://127.0.0.1/private"}), &NeverCancelled),
            Err(ReadToolError::InvalidArguments(_))
        ));
    }

    #[test]
    fn special_address_and_allocation_corpus_fails_closed() {
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.254",
            "127.255.255.254",
            "169.254.1.1",
            "172.16.0.1",
            "172.31.255.254",
            "192.0.0.9",
            "192.0.2.1",
            "192.88.99.2",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "64:ff9b:1::1",
            "100::1",
            "2000::1",
            "2001::1",
            "2001:2::1",
            "2001:10::1",
            "2001:1000::1",
            "2001:db8::1",
            "2001:c000::1",
            "2002::1",
            "2003:4000::1",
            "2420::1",
            "2610:200::1",
            "2611::1",
            "2620:200::1",
            "2621::1",
            "2640::1",
            "2810::1",
            "2a20::1",
            "2c10::1",
            "2d00::1",
            "3fff::1",
            "5f00::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
        ] {
            let address: IpAddr = address.parse().expect("address corpus entry");
            assert!(!is_public_address(address), "accepted {address}");
        }

        for address in [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.1",
            "172.15.255.255",
            "172.32.0.1",
            "192.31.196.1",
            "192.52.193.1",
            "192.175.48.1",
            "203.0.112.1",
            "203.0.114.1",
            "223.255.255.254",
            "2001:1::1",
            "2001:3::1",
            "2001:4:112::1",
            "2001:20::1",
            "2001:30::1",
            "2001:4860:4860::8888",
            "2003:3fff::1",
            "2404:6800:4006::1",
            "241f::1",
            "2606:4700:4700::1111",
            "2610:1ff::1",
            "2620:1ff::1",
            "263f::1",
            "2800:3f0:4001::1",
            "280f::1",
            "2a00:1450:4009::1",
            "2a1f::1",
            "2c0f:fb50:4003::1",
        ] {
            let address: IpAddr = address.parse().expect("address corpus entry");
            assert!(is_public_address(address), "rejected {address}");
        }
    }

    #[test]
    fn hostname_and_obfuscated_loopback_destinations_fail_closed() {
        let config = WebAccessConfig {
            enabled: true,
            allow_public_internet: true,
            ..WebAccessConfig::default()
        };
        let tools = WebReadTool::suite(config, None).expect("fetch tool");
        for url in [
            "http://localhost/private",
            "http://127.1/private",
            "http://2130706433/private",
            "http://0x7f000001/private",
            "http://0177.0.0.1/private",
            "http://[::1]/private",
            "http://[::ffff:127.0.0.1]/private",
        ] {
            assert!(
                matches!(
                    tools[0].execute(&json!({"url": url}), &NeverCancelled),
                    Err(ReadToolError::InvalidArguments(_))
                ),
                "accepted {url}"
            );
        }
        for url in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "https://user@example.com/",
            "https://example.com/#fragment",
            " https://example.com/",
        ] {
            assert!(canonical_fetch_url(url).is_err(), "accepted {url}");
        }
    }

    #[test]
    fn html_text_extraction_handles_adversarial_markup_without_cascading_entities() {
        assert_eq!(
            html_to_text(
                r#"<scripture data-note="ignore > still ignored">kept</scripture>
                   <!-- hidden instruction -->
                   <SCRIPT title="> ignored">bad()</SCRIPT>
                   <style>.bad { display: block }</style>
                   <noscript>fallback instruction</noscript>
                   <stylesheet>also kept</stylesheet>
                   <p>A&nbsp;&amp;&lt;&gt;&quot;&#39;&#x21;&#33;</p>
                   <p>&amp;lt;</p>"#
            ),
            "kept also kept A &<>\"'!! &lt;"
        );
        assert_eq!(
            html_to_text("before<script>bad()</script>after"),
            "before after"
        );
        assert_eq!(html_to_text("before<script>bad()"), "before");
        assert_eq!(html_to_text("before<!-- hidden"), "before");
        assert_eq!(html_to_text(r#"<script src="x" />after"#), "after");
    }
}
