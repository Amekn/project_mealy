use mealy_policy::RiskClass;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginManifest {
    pub plugin_id: String,
    pub name: String,
    pub version: String,
    pub schema_version: u32,
    pub description: String,
    pub entrypoint: PluginEntrypoint,
    pub permissions: Vec<String>,
    pub tools: Vec<PluginTool>,
    pub config_schema: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PluginEntrypoint {
    InProcess { crate_name: String },
    ChildProcess { command: String, args: Vec<String> },
    Wasm { module_ref: String },
    Remote { url: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginTool {
    pub name: String,
    pub capability: String,
    pub risk_class: RiskClass,
}
