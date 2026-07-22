//! Deterministic MCP stdio fixture used only for boundary conformance tests.

use serde_json::{Value, json};
use std::{
    io::{BufRead as _, BufReader, Write as _},
    process::Command,
    thread,
    time::Duration,
};

const PROTOCOL_VERSION: &str = "2025-11-25";

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "good".to_owned());
    if mode == "child" {
        return;
    }
    if mode == "extra-stdout" {
        println!("this is not JSON-RPC");
    }
    if mode == "stderr-flood" {
        let _ = std::io::stderr().write_all(&vec![b'x'; 70 * 1024]);
    }
    let input = std::io::stdin();
    let mut output = std::io::stdout().lock();
    for line in BufReader::new(input.lock()).lines() {
        let Ok(line) = line else {
            return;
        };
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            return;
        };
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            continue;
        };
        let Some(id) = message.get("id").cloned() else {
            continue;
        };
        if mode == "malformed" && method == "initialize" {
            let _ = output.write_all(b"{definitely-not-json}\n");
            let _ = output.flush();
            continue;
        }
        let response = match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": if mode == "wrong-version" {
                        "2025-06-18"
                    } else {
                        PROTOCOL_VERSION
                    },
                    "capabilities": {"tools": {"listChanged": true}},
                    "serverInfo": {
                        "name": "mealy-mcp-fixture",
                        "version": "1.0.0"
                    }
                }
            }),
            "tools/list" => list_tools(&message, &id, &mode),
            "tools/call" => call_tool(&message, &id),
            "ping" => json!({"jsonrpc": "2.0", "id": id, "result": {}}),
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": "unsupported fixture method"}
            }),
        };
        let Ok(mut bytes) = serde_json::to_vec(&response) else {
            return;
        };
        bytes.push(b'\n');
        if output.write_all(&bytes).is_err() || output.flush().is_err() {
            return;
        }
    }
    if mode == "trailing-extra-stdout" {
        let _ = output.write_all(b"this trailing line is not JSON-RPC\n");
        let _ = output.flush();
    }
}

fn list_tools(message: &Value, id: &Value, mode: &str) -> Value {
    let cursor = message
        .get("params")
        .and_then(|params| params.get("cursor"))
        .and_then(Value::as_str);
    if cursor == Some("page-2") {
        return json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {"tools": [sleep_definition()]}
        });
    }
    let mut add = add_definition();
    if mode == "drift" {
        add["description"] = Value::String("A changed, unreviewed definition".to_owned());
    }
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "tools": [add, boundary_definition()],
            "nextCursor": "page-2"
        }
    })
}

fn add_definition() -> Value {
    json!({
        "name": "add",
        "description": "Adds two integers inside the isolated fixture",
        "inputSchema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "left": {"type": "integer"},
                "right": {"type": "integer"}
            },
            "required": ["left", "right"]
        },
        "outputSchema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {"sum": {"type": "integer"}},
            "required": ["sum"]
        },
        "annotations": {"readOnlyHint": true}
    })
}

fn boundary_definition() -> Value {
    json!({
        "name": "inspect_boundary",
        "description": "Reports fixture-observed environment, filesystem, and process isolation",
        "inputSchema": {"type": "object", "additionalProperties": false},
        "outputSchema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "environmentCount": {"type": "integer"},
                "passwdReadable": {"type": "boolean"},
                "spawnSucceeded": {"type": "boolean"}
            },
            "required": ["environmentCount", "passwdReadable", "spawnSucceeded"]
        }
    })
}

fn sleep_definition() -> Value {
    json!({
        "name": "sleep",
        "description": "Waits for a bounded fixture duration",
        "inputSchema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "milliseconds": {"type": "integer", "minimum": 0, "maximum": 10000}
            },
            "required": ["milliseconds"]
        }
    })
}

fn call_tool(message: &Value, id: &Value) -> Value {
    let name = message
        .get("params")
        .and_then(|params| params.get("name"))
        .and_then(Value::as_str);
    let arguments = message
        .get("params")
        .and_then(|params| params.get("arguments"));
    let structured = match name {
        Some("add") => {
            let left = arguments
                .and_then(|value| value.get("left"))
                .and_then(Value::as_i64)
                .unwrap_or_default();
            let right = arguments
                .and_then(|value| value.get("right"))
                .and_then(Value::as_i64)
                .unwrap_or_default();
            json!({"sum": left.saturating_add(right)})
        }
        Some("inspect_boundary") => {
            let mut spawned = Command::new("/mcp/server").arg("child").spawn();
            let spawn_succeeded = spawned.is_ok();
            if let Ok(child) = spawned.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
            json!({
                "environmentCount": std::env::vars_os().count(),
                "passwdReadable": std::fs::read("/etc/passwd").is_ok(),
                "spawnSucceeded": spawn_succeeded
            })
        }
        Some("sleep") => {
            let milliseconds = arguments
                .and_then(|value| value.get("milliseconds"))
                .and_then(Value::as_u64)
                .unwrap_or_default()
                .min(10_000);
            thread::sleep(Duration::from_millis(milliseconds));
            json!({"sleptMilliseconds": milliseconds})
        }
        _ => {
            return json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32602, "message": "unknown fixture tool"}
            });
        }
    };
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{"type": "text", "text": structured.to_string()}],
            "structuredContent": structured,
            "isError": false
        }
    })
}
