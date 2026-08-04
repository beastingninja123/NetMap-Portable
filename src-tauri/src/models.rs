use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectInfo {
    pub id: String,
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Diagnostics {
    pub version: String,
    pub data_root: String,
    pub portable_mode: bool,
    pub sqlite_version: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportProgress {
    pub import_id: String,
    pub phase: String,
    pub processed: u64,
    pub accepted: u64,
    pub skipped: u64,
    pub total_bytes: Option<u64>,
    pub completed: bool,
    pub cancelled: bool,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CsvMapping {
    pub source_ip: String,
    pub destination_ip: String,
    pub source_port: Option<String>,
    pub destination_port: Option<String>,
    pub protocol: Option<String>,
    pub timestamp: Option<String>,
    pub bytes: Option<String>,
    pub packets: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CsvPreview {
    pub headers: Vec<String>,
    pub detected_format: Option<String>,
    pub suggested_mapping: Option<CsvMapping>,
    pub rows: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub import_id: String,
    pub accepted: u64,
    pub skipped: u64,
    pub cancelled: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GraphFilters {
    pub import_ids: Option<Vec<String>>,
    pub ip_contains: Option<String>,
    pub protocols: Option<Vec<String>>,
    pub min_bytes: Option<i64>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphNode {
    pub id: i64,
    pub ip: String,
    pub hostname: Option<String>,
    pub version: i64,
    pub total_bytes: i64,
    pub total_packets: i64,
    pub first_seen: Option<i64>,
    pub last_seen: Option<i64>,
    pub imports: Vec<String>,
    pub tags: Vec<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphEdge {
    pub id: i64,
    pub source: i64,
    pub target: i64,
    pub source_port: Option<i64>,
    pub destination_port: Option<i64>,
    pub protocol: String,
    pub bytes: i64,
    pub packets: i64,
    pub first_seen: Option<i64>,
    pub last_seen: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphResult {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedViewRecord {
    pub id: String,
    pub name: String,
    pub state: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct FlowRecord {
    pub source_ip: String,
    pub destination_ip: String,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: String,
    pub bytes: u64,
    pub packets: u64,
    pub timestamp: Option<i64>,
}
