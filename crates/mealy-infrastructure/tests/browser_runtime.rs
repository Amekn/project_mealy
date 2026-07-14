//! Opt-in real Chrome Headless Shell process-boundary evidence.

use mealy_application::{
    BROWSER_CDP_PROTOCOL_VERSION, BrowserConfig, CancellationProbe, ReadOnlyTool, WebAccessConfig,
    sha256_digest,
};
use mealy_infrastructure::{
    BrowserReadTool, inspect_browser_bundle, probe_browser_bundle_product, publish_browser_bundle,
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use tempfile::TempDir;

struct NeverCancelled;

impl CancellationProbe for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct MockOrigin {
    address: std::net::SocketAddr,
    unsafe_requests: Arc<std::sync::atomic::AtomicUsize>,
    stop: Arc<AtomicBool>,
    server: Option<thread::JoinHandle<()>>,
}

impl MockOrigin {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("local origin");
        listener.set_nonblocking(true).expect("nonblocking origin");
        let address = listener.local_addr().expect("origin address");
        let stop = Arc::new(AtomicBool::new(false));
        let unsafe_requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server_stop = Arc::clone(&stop);
        let server_unsafe_requests = Arc::clone(&unsafe_requests);
        let server = thread::spawn(move || {
            let mut connections = Vec::new();
            while !server_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let connection_unsafe_requests = Arc::clone(&server_unsafe_requests);
                        connections.push(thread::spawn(move || {
                            stream
                                .set_read_timeout(Some(Duration::from_secs(2)))
                                .expect("origin read timeout");
                            serve_page(&mut stream, &connection_unsafe_requests, address);
                        }));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("origin failed: {error}"),
                }
            }
            for connection in connections {
                connection.join().expect("join origin connection");
            }
        });
        Self {
            address,
            unsafe_requests,
            stop,
            server: Some(server),
        }
    }
}

impl Drop for MockOrigin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(server) = self.server.take() {
            server.join().expect("join origin");
        }
    }
}

fn serve_page(
    stream: &mut TcpStream,
    unsafe_requests: &std::sync::atomic::AtomicUsize,
    address: std::net::SocketAddr,
) {
    let mut request = [0_u8; 8192];
    let Ok(read) = stream.read(&mut request) else {
        return;
    };
    if read == 0 {
        return;
    }
    let request = String::from_utf8_lossy(&request[..read]);
    if !request.starts_with("GET ") && !request.starts_with("HEAD ")
        || request.starts_with("GET /socket ")
    {
        unsafe_requests.fetch_add(1, Ordering::SeqCst);
    }
    if request.starts_with("GET /download ") {
        let body = b"bounded browser attachment evidence\n";
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"evidence.bin\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .expect("write browser download headers");
        stream.write_all(body).expect("write browser download");
        return;
    }
    if request.starts_with("GET /download-large ") {
        let body = vec![b'x'; 512 * 1024 + 1];
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"large.bin\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .expect("write oversized browser download headers");
        stream
            .write_all(&body)
            .expect("write oversized browser download");
        return;
    }
    let body = if request.starts_with("GET /details ") {
        "<!doctype html><title>Details</title><main>Rendered detail evidence</main>"
    } else if request.starts_with("GET /search?scope=docs&query=durable+browser+evidence ") {
        "<!doctype html><title>Search</title><main>Rendered GET form evidence</main>"
    } else {
        return serve_start_page(stream, address);
    };
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("write browser response");
}

fn serve_start_page(stream: &mut TcpStream, address: std::net::SocketAddr) {
    let body = format!(
        "<!doctype html><title>Start</title><main>Rendered start evidence <a href=\"/details\">Details</a><a href=\"/download\">Download evidence</a><a href=\"/download-large\">Oversized download</a><output id=\"button-result\">Button not activated</output><button type=\"button\" onclick=\"document.getElementById('button-result').textContent='Rendered button evidence';fetch('/mutate',{{method:'POST',body:'forbidden'}}).catch(()=>{{}})\">Show button evidence</button><form action=\"/search?scope=docs\" method=\"get\"><label>Query <input type=\"search\" name=\"query\"></label><input type=\"hidden\" name=\"hiddenSecret\" value=\"must-not-submit\"><button>Search</button></form><form action=\"/mutate\" method=\"post\"><label>Unsafe <input type=\"text\" name=\"unsafe\"></label><button>Submit forbidden</button></form><label>Password <input type=\"password\" name=\"password\"></label></main><script>fetch('/mutate',{{method:'POST',body:'forbidden'}}).catch(()=>{{}});try{{new WebSocket('ws://{address}/socket')}}catch(_){{}}</script>"
    );
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("write start browser response");
}

fn configured_browser_tool() -> (TempDir, MockOrigin, BrowserReadTool, String) {
    let source = PathBuf::from(std::env::var_os("MEALY_BROWSER_BUNDLE").expect("bundle path"));
    let inspected = inspect_browser_bundle(&source, None).expect("inspect browser bundle");
    let probe = probe_browser_bundle_product(
        std::path::Path::new("/usr/bin/bwrap"),
        &source,
        Some(inspected.bundle_digest()),
    )
    .expect("sandboxed browser probe");
    let product = probe.product().to_owned();
    let temporary = TempDir::new().expect("temporary home");
    let home = temporary.path().join("home");
    fs::create_dir(&home).expect("home");
    let destination =
        publish_browser_bundle(&inspected, &home.join("browser-runtimes")).expect("publish bundle");
    assert_eq!(
        destination,
        home.join("browser-runtimes")
            .join(inspected.bundle_digest())
    );
    let origin = MockOrigin::start();
    let config = BrowserConfig::new(
        true,
        format!("browser-runtimes/{}", inspected.bundle_digest()),
        inspected.bundle_digest().to_owned(),
        "chrome-headless-shell".to_owned(),
        inspected.executable_digest().to_owned(),
        product.clone(),
        BROWSER_CDP_PROTOCOL_VERSION.to_owned(),
    )
    .expect("browser config");
    let web = WebAccessConfig {
        enabled: true,
        allow_public_internet: false,
        allowed_domains: Vec::new(),
        allowed_origins: vec![format!("http://{}", origin.address)],
        search: None,
    };
    let tool = BrowserReadTool::load(
        &home,
        std::path::Path::new("/usr/bin/bwrap"),
        std::path::Path::new(env!("CARGO_BIN_EXE_mealy-browser-worker")),
        config,
        web,
    )
    .expect("load browser tool");
    (temporary, origin, tool, product)
}

/// Runs only in the explicit release environment because the reviewed browser bundle is hundreds
/// of megabytes and is not fetched implicitly by ordinary builds.
#[test]
#[ignore = "set MEALY_BROWSER_BUNDLE to a reviewed Chrome Headless Shell bundle"]
#[allow(clippy::too_many_lines)]
fn real_headless_shell_is_isolated_rendered_bounded_and_can_activate_read_only_elements() {
    let (_temporary, origin, tool, product) = configured_browser_tool();
    let address = origin.address;
    let output = tool
        .execute(
            &json!({
                "url": format!("http://{address}/"),
                "waitMs": 300,
                "maximumTextBytes": 4096,
                "maximumElements": 16,
                "captureScreenshot": true,
                "followLink": {"name": "Details"}
            }),
            &NeverCancelled,
        )
        .expect("render browser page");
    let result = serde_json::from_slice::<Value>(&output.bytes).expect("browser JSON");
    assert_eq!(result["browserProduct"], product);
    assert!(result["activatedElement"].is_null());
    assert_eq!(result["title"], "Details");
    assert!(
        result["text"]
            .as_str()
            .expect("text")
            .contains("Rendered detail evidence")
    );
    assert_eq!(result["followedLink"]["name"], "Details");
    assert_eq!(result["screenshot"]["mediaType"], "image/png");

    let button_output = tool
        .execute(
            &json!({
                "url": format!("http://{address}/"),
                "waitMs": 300,
                "maximumTextBytes": 4096,
                "maximumElements": 16,
                "activateElement": {"role": "button", "name": "Show button evidence"}
            }),
            &NeverCancelled,
        )
        .expect("activate form-free button");
    let button_result =
        serde_json::from_slice::<Value>(&button_output.bytes).expect("button browser JSON");
    assert_eq!(button_result["activatedElement"]["role"], "button");
    assert_eq!(
        button_result["activatedElement"]["name"],
        "Show button evidence"
    );
    assert!(
        button_result["text"]
            .as_str()
            .expect("button text")
            .contains("Rendered button evidence")
    );

    let fill_output = tool
        .execute(
            &json!({
                "url": format!("http://{address}/"),
                "waitMs": 300,
                "maximumTextBytes": 4096,
                "maximumElements": 16,
                "fillElement": {
                    "role": "searchbox",
                    "name": "Query",
                    "value": "durable browser evidence",
                    "submitGetForm": true
                }
            }),
            &NeverCancelled,
        )
        .expect("fill and submit exact GET form control");
    let fill_result =
        serde_json::from_slice::<Value>(&fill_output.bytes).expect("fill browser JSON");
    assert_eq!(fill_result["filledElement"]["role"], "searchbox");
    assert_eq!(fill_result["filledElement"]["submittedGetForm"], true);
    assert!(
        fill_result["filledElement"]["submittedUrl"]
            .as_str()
            .expect("submitted URL")
            .ends_with("/search?scope=docs&query=durable+browser+evidence")
    );
    assert!(
        fill_result["text"]
            .as_str()
            .expect("GET form text")
            .contains("Rendered GET form evidence")
    );
    assert!(!fill_result.to_string().contains("must-not-submit"));

    let download_output = tool
        .execute(
            &json!({
                "url": format!("http://{address}/"),
                "waitMs": 300,
                "maximumTextBytes": 4096,
                "maximumElements": 16,
                "downloadLink": {"name": "Download evidence"}
            }),
            &NeverCancelled,
        )
        .expect("capture bounded same-origin attachment");
    let download_result =
        serde_json::from_slice::<Value>(&download_output.bytes).expect("download browser JSON");
    let expected_download = b"bounded browser attachment evidence\n";
    assert_eq!(
        download_result["download"]["dataBase64"],
        "Ym91bmRlZCBicm93c2VyIGF0dGFjaG1lbnQgZXZpZGVuY2UK"
    );
    assert_eq!(
        download_result["download"]["sha256Digest"],
        sha256_digest(expected_download)
    );
    assert_eq!(
        download_result["download"]["sizeBytes"],
        expected_download.len()
    );
    assert!(
        download_result["download"]["url"]
            .as_str()
            .expect("download URL")
            .ends_with("/download")
    );
    let oversized_download = tool.execute(
        &json!({
            "url": format!("http://{address}/"),
            "waitMs": 300,
            "downloadLink": {"name": "Oversized download"}
        }),
        &NeverCancelled,
    );
    assert!(oversized_download.is_err());

    let submit = tool.execute(
        &json!({
            "url": format!("http://{address}/"),
            "waitMs": 300,
            "activateElement": {"role": "button", "name": "Submit forbidden"}
        }),
        &NeverCancelled,
    );
    assert!(submit.is_err());
    let post_form = tool.execute(
        &json!({
            "url": format!("http://{address}/"),
            "waitMs": 300,
            "fillElement": {
                "role": "textbox",
                "name": "Unsafe",
                "value": "forbidden",
                "submitGetForm": true
            }
        }),
        &NeverCancelled,
    );
    assert!(post_form.is_err());
    let password = tool.execute(
        &json!({
            "url": format!("http://{address}/"),
            "waitMs": 300,
            "fillElement": {
                "role": "textbox",
                "name": "Password",
                "value": "forbidden"
            }
        }),
        &NeverCancelled,
    );
    assert!(password.is_err());
    assert_eq!(tool.invocation_count(), 8);
    assert_eq!(origin.unsafe_requests.load(Ordering::SeqCst), 0);
}
