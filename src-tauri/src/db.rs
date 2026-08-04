use crate::error::{AppError, Result};
use crate::models::{FlowRecord, GraphEdge, GraphFilters, GraphNode, GraphResult, SavedViewRecord};
use rusqlite::{params, params_from_iter, types::Value, Connection, OptionalExtension};
use std::collections::{HashMap, HashSet};
use std::path::Path;

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous = NORMAL;
CREATE TABLE IF NOT EXISTS imports (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('csv','pcap')),
  source_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('running','complete','cancelled','failed')),
  accepted INTEGER NOT NULL DEFAULT 0,
  skipped INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  completed_at INTEGER
);
CREATE TABLE IF NOT EXISTS nodes (
  id INTEGER PRIMARY KEY,
  ip TEXT NOT NULL UNIQUE,
  ip_version INTEGER NOT NULL,
  total_bytes INTEGER NOT NULL DEFAULT 0,
  total_packets INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS flows (
  id INTEGER PRIMARY KEY,
  source_node_id INTEGER NOT NULL REFERENCES nodes(id),
  destination_node_id INTEGER NOT NULL REFERENCES nodes(id),
  source_port INTEGER NOT NULL DEFAULT -1,
  destination_port INTEGER NOT NULL DEFAULT -1,
  protocol TEXT NOT NULL,
  bytes INTEGER NOT NULL DEFAULT 0,
  packets INTEGER NOT NULL DEFAULT 0,
  first_seen INTEGER,
  last_seen INTEGER,
  UNIQUE(source_node_id,destination_node_id,source_port,destination_port,protocol)
);
CREATE TABLE IF NOT EXISTS flow_imports (
  flow_id INTEGER NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
  import_id TEXT NOT NULL REFERENCES imports(id) ON DELETE CASCADE,
  bytes INTEGER NOT NULL DEFAULT 0,
  packets INTEGER NOT NULL DEFAULT 0,
  first_seen INTEGER,
  last_seen INTEGER,
  PRIMARY KEY(flow_id,import_id)
);
CREATE TABLE IF NOT EXISTS tags (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  color TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS node_tags (
  node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  PRIMARY KEY(node_id,tag_id)
);
CREATE TABLE IF NOT EXISTS notes (
  id INTEGER PRIMARY KEY,
  node_id INTEGER REFERENCES nodes(id) ON DELETE CASCADE,
  flow_id INTEGER REFERENCES flows(id) ON DELETE CASCADE,
  body TEXT NOT NULL,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  CHECK((node_id IS NULL) != (flow_id IS NULL))
);
CREATE TABLE IF NOT EXISTS saved_views (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  filters_json TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_flows_source ON flows(source_node_id);
CREATE INDEX IF NOT EXISTS idx_flows_destination ON flows(destination_node_id);
CREATE INDEX IF NOT EXISTS idx_flows_protocol ON flows(protocol);
CREATE INDEX IF NOT EXISTS idx_flows_time ON flows(first_seen,last_seen);
CREATE INDEX IF NOT EXISTS idx_flow_imports_import ON flow_imports(import_id);
CREATE INDEX IF NOT EXISTS idx_notes_node ON notes(node_id);
"#;

pub fn open(path: &Path) -> Result<Connection> {
    let connection = Connection::open(path)?;
    connection.busy_timeout(std::time::Duration::from_secs(10))?;
    connection.execute_batch(SCHEMA)?;
    Ok(connection)
}

pub fn start_import(
    connection: &Connection,
    id: &str,
    kind: &str,
    source_name: &str,
) -> Result<()> {
    connection.execute(
        "INSERT INTO imports(id,kind,source_name,status) VALUES(?1,?2,?3,'running')",
        params![id, kind, source_name],
    )?;
    Ok(())
}

pub fn insert_batch(
    connection: &mut Connection,
    import_id: &str,
    flows: &[FlowRecord],
) -> Result<()> {
    let transaction = connection.transaction()?;
    {
        let mut insert_node = transaction.prepare_cached(
            "INSERT INTO nodes(ip,ip_version) VALUES(?1,?2) ON CONFLICT(ip) DO NOTHING",
        )?;
        let mut select_node = transaction.prepare_cached("SELECT id FROM nodes WHERE ip=?1")?;
        let mut upsert_flow = transaction.prepare_cached(
            "INSERT INTO flows(source_node_id,destination_node_id,source_port,destination_port,protocol,bytes,packets,first_seen,last_seen)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?8)
             ON CONFLICT(source_node_id,destination_node_id,source_port,destination_port,protocol)
             DO UPDATE SET bytes=bytes+excluded.bytes,packets=packets+excluded.packets,
               first_seen=CASE WHEN excluded.first_seen IS NULL THEN first_seen WHEN first_seen IS NULL THEN excluded.first_seen ELSE min(first_seen,excluded.first_seen) END,
               last_seen=CASE WHEN excluded.last_seen IS NULL THEN last_seen WHEN last_seen IS NULL THEN excluded.last_seen ELSE max(last_seen,excluded.last_seen) END"
        )?;
        let mut select_flow = transaction.prepare_cached(
            "SELECT id FROM flows WHERE source_node_id=?1 AND destination_node_id=?2
             AND source_port=?3 AND destination_port=?4 AND protocol=?5",
        )?;
        let mut upsert_import = transaction.prepare_cached(
            "INSERT INTO flow_imports(flow_id,import_id,bytes,packets,first_seen,last_seen)
             VALUES(?1,?2,?3,?4,?5,?5)
             ON CONFLICT(flow_id,import_id) DO UPDATE SET
               bytes=bytes+excluded.bytes,packets=packets+excluded.packets,
               first_seen=CASE WHEN excluded.first_seen IS NULL THEN first_seen WHEN first_seen IS NULL THEN excluded.first_seen ELSE min(first_seen,excluded.first_seen) END,
               last_seen=CASE WHEN excluded.last_seen IS NULL THEN last_seen WHEN last_seen IS NULL THEN excluded.last_seen ELSE max(last_seen,excluded.last_seen) END",
        )?;

        for flow in flows {
            insert_node.execute(params![
                flow.source_ip,
                if flow.source_ip.contains(':') { 6 } else { 4 }
            ])?;
            insert_node.execute(params![
                flow.destination_ip,
                if flow.destination_ip.contains(':') {
                    6
                } else {
                    4
                }
            ])?;
            let source_id: i64 = select_node.query_row([&flow.source_ip], |row| row.get(0))?;
            let destination_id: i64 =
                select_node.query_row([&flow.destination_ip], |row| row.get(0))?;
            let source_port = flow.source_port.map(i64::from).unwrap_or(-1);
            let destination_port = flow.destination_port.map(i64::from).unwrap_or(-1);
            let bytes = flow.bytes.min(i64::MAX as u64) as i64;
            let packets = flow.packets.min(i64::MAX as u64) as i64;
            upsert_flow.execute(params![
                source_id,
                destination_id,
                source_port,
                destination_port,
                flow.protocol,
                bytes,
                packets,
                flow.timestamp
            ])?;
            let flow_id: i64 = select_flow.query_row(
                params![
                    source_id,
                    destination_id,
                    source_port,
                    destination_port,
                    flow.protocol
                ],
                |row| row.get(0),
            )?;
            upsert_import.execute(params![flow_id, import_id, bytes, packets, flow.timestamp])?;
        }
    }
    transaction.commit()?;
    Ok(())
}

pub fn finish_import(
    connection: &Connection,
    id: &str,
    accepted: u64,
    skipped: u64,
    status: &str,
    error: Option<&str>,
) -> Result<()> {
    connection.execute(
        "UPDATE imports SET status=?2,accepted=?3,skipped=?4,error=?5,completed_at=unixepoch() WHERE id=?1",
        params![id, status, accepted.min(i64::MAX as u64) as i64, skipped.min(i64::MAX as u64) as i64, error],
    )?;
    rebuild_node_totals(connection)?;
    Ok(())
}

pub fn delete_import(connection: &mut Connection, id: &str) -> Result<()> {
    let transaction = connection.transaction()?;
    let changed = transaction.execute("DELETE FROM imports WHERE id=?1", [id])?;
    if changed == 0 {
        return Err(AppError::NotFound(format!("import {id}")));
    }
    transaction.execute_batch(
        "UPDATE flows SET
           bytes=COALESCE((SELECT sum(bytes) FROM flow_imports WHERE flow_id=flows.id),0),
           packets=COALESCE((SELECT sum(packets) FROM flow_imports WHERE flow_id=flows.id),0),
           first_seen=(SELECT min(first_seen) FROM flow_imports WHERE flow_id=flows.id),
           last_seen=(SELECT max(last_seen) FROM flow_imports WHERE flow_id=flows.id);
         DELETE FROM flows WHERE NOT EXISTS(SELECT 1 FROM flow_imports WHERE flow_id=flows.id);
         DELETE FROM nodes WHERE NOT EXISTS(
           SELECT 1 FROM flows WHERE source_node_id=nodes.id OR destination_node_id=nodes.id
         );",
    )?;
    rebuild_node_totals(&transaction)?;
    transaction.commit()?;
    Ok(())
}

fn rebuild_node_totals(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "UPDATE nodes SET
           total_bytes=COALESCE((SELECT sum(bytes) FROM flows WHERE source_node_id=nodes.id OR destination_node_id=nodes.id),0),
           total_packets=COALESCE((SELECT sum(packets) FROM flows WHERE source_node_id=nodes.id OR destination_node_id=nodes.id),0);",
    )?;
    Ok(())
}

fn filter_sql(filters: &GraphFilters) -> (String, Vec<Value>, u32) {
    let mut clauses = vec!["1=1".to_string()];
    let mut values = Vec::new();
    if let Some(ids) = filters.import_ids.as_ref().filter(|ids| !ids.is_empty()) {
        let placeholders = (0..ids.len()).map(|_| "?").collect::<Vec<_>>().join(",");
        clauses.push(format!(
            "EXISTS(SELECT 1 FROM flow_imports fi WHERE fi.flow_id=f.id AND fi.import_id IN ({placeholders}))"
        ));
        values.extend(ids.iter().cloned().map(Value::Text));
    }
    if let Some(ip) = filters
        .ip_contains
        .as_ref()
        .filter(|value| !value.is_empty())
    {
        clauses.push("(sn.ip LIKE ? OR dn.ip LIKE ?)".into());
        let pattern = format!("%{}%", ip.replace('%', "\\%").replace('_', "\\_"));
        values.push(Value::Text(pattern.clone()));
        values.push(Value::Text(pattern));
    }
    if let Some(protocols) = filters.protocols.as_ref().filter(|items| !items.is_empty()) {
        let placeholders = (0..protocols.len())
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");
        clauses.push(format!("f.protocol IN ({placeholders})"));
        values.extend(
            protocols
                .iter()
                .map(|item| Value::Text(item.to_ascii_uppercase())),
        );
    }
    if let Some(value) = filters.min_bytes {
        clauses.push("f.bytes>=?".into());
        values.push(Value::Integer(value.max(0)));
    }
    if let Some(value) = filters.start_time {
        clauses.push("f.last_seen>=?".into());
        values.push(Value::Integer(value));
    }
    if let Some(value) = filters.end_time {
        clauses.push("f.first_seen<=?".into());
        values.push(Value::Integer(value));
    }
    (
        clauses.join(" AND "),
        values,
        filters.limit.unwrap_or(5_000).clamp(1, 50_000),
    )
}

pub fn query_graph(connection: &Connection, filters: &GraphFilters) -> Result<GraphResult> {
    let (where_sql, mut values, limit) = filter_sql(filters);
    values.push(Value::Integer((limit + 1) as i64));
    let sql = format!(
        "SELECT f.id,f.source_node_id,f.destination_node_id,f.source_port,f.destination_port,
         f.protocol,f.bytes,f.packets,f.first_seen,f.last_seen,sn.ip,dn.ip
         FROM flows f JOIN nodes sn ON sn.id=f.source_node_id JOIN nodes dn ON dn.id=f.destination_node_id
         WHERE {where_sql} ORDER BY f.bytes DESC LIMIT ?"
    );
    let mut statement = connection.prepare(&sql)?;
    let mut rows = statement.query(params_from_iter(values))?;
    let mut edges = Vec::new();
    let mut node_ids = HashSet::new();
    while let Some(row) = rows.next()? {
        let source = row.get(1)?;
        let target = row.get(2)?;
        node_ids.insert(source);
        node_ids.insert(target);
        let source_port: i64 = row.get(3)?;
        let destination_port: i64 = row.get(4)?;
        edges.push(GraphEdge {
            id: row.get(0)?,
            source,
            target,
            source_port: (source_port >= 0).then_some(source_port),
            destination_port: (destination_port >= 0).then_some(destination_port),
            protocol: row.get(5)?,
            bytes: row.get(6)?,
            packets: row.get(7)?,
            first_seen: row.get(8)?,
            last_seen: row.get(9)?,
        });
    }
    let truncated = edges.len() > limit as usize;
    edges.truncate(limit as usize);
    let mut nodes_by_id = HashMap::new();
    let mut node_statement = connection.prepare(
        "SELECT n.id,n.ip,n.ip_version,n.total_bytes,n.total_packets,
           (SELECT min(f.first_seen) FROM flows f WHERE f.source_node_id=n.id OR f.destination_node_id=n.id),
           (SELECT max(f.last_seen) FROM flows f WHERE f.source_node_id=n.id OR f.destination_node_id=n.id),
           COALESCE((SELECT json_group_array(name) FROM (
             SELECT DISTINCT i.source_name AS name FROM imports i
             JOIN flow_imports fi ON fi.import_id=i.id
             JOIN flows f ON f.id=fi.flow_id
             WHERE f.source_node_id=n.id OR f.destination_node_id=n.id
           )), '[]'),
           COALESCE((SELECT json_group_array(name) FROM (
             SELECT DISTINCT t.name AS name FROM tags t
             JOIN node_tags nt ON nt.tag_id=t.id WHERE nt.node_id=n.id ORDER BY t.name
           )), '[]'),
           (SELECT body FROM notes WHERE node_id=n.id ORDER BY updated_at DESC LIMIT 1)
         FROM nodes n WHERE n.id=?1",
    )?;
    for id in node_ids {
        if let Some(node) = node_statement
            .query_row([id], |row| {
                Ok(GraphNode {
                    id: row.get(0)?,
                    ip: row.get(1)?,
                    version: row.get(2)?,
                    total_bytes: row.get(3)?,
                    total_packets: row.get(4)?,
                    first_seen: row.get(5)?,
                    last_seen: row.get(6)?,
                    imports: parse_json_list(row.get::<_, String>(7)?),
                    tags: parse_json_list(row.get::<_, String>(8)?),
                    notes: row.get(9)?,
                })
            })
            .optional()?
        {
            nodes_by_id.insert(id, node);
        }
    }
    Ok(GraphResult {
        nodes: nodes_by_id.into_values().collect(),
        edges,
        truncated,
    })
}

fn parse_json_list(value: String) -> Vec<String> {
    serde_json::from_str(&value).unwrap_or_default()
}

pub fn save_view(
    connection: &Connection,
    id: &str,
    name: &str,
    state: &serde_json::Value,
) -> Result<()> {
    if name.trim().is_empty() {
        return Err(AppError::Invalid("view name cannot be empty".into()));
    }
    let json = serde_json::to_string(state)
        .map_err(|error| AppError::Invalid(format!("invalid filters: {error}")))?;
    connection.execute(
        "INSERT INTO saved_views(id,name,filters_json) VALUES(?1,?2,?3)
         ON CONFLICT(id) DO UPDATE SET name=excluded.name,filters_json=excluded.filters_json,updated_at=unixepoch()",
        params![id, name.trim(), json],
    )?;
    Ok(())
}

pub fn list_views(connection: &Connection) -> Result<Vec<SavedViewRecord>> {
    let mut statement = connection.prepare(
        "SELECT id,name,filters_json FROM saved_views ORDER BY updated_at DESC,name COLLATE NOCASE",
    )?;
    let rows = statement.query_map([], |row| {
        let json: String = row.get(2)?;
        Ok(SavedViewRecord {
            id: row.get(0)?,
            name: row.get(1)?,
            state: serde_json::from_str(&json).unwrap_or(serde_json::Value::Null),
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub fn set_node_metadata(
    connection: &mut Connection,
    node_id: i64,
    tags: &[String],
    notes: Option<&str>,
) -> Result<()> {
    if tags.len() > 50 {
        return Err(AppError::Invalid(
            "a node cannot have more than 50 tags".into(),
        ));
    }
    let cleaned = tags
        .iter()
        .map(|tag| tag.trim())
        .filter(|tag| !tag.is_empty())
        .collect::<HashSet<_>>();
    if cleaned
        .iter()
        .any(|tag| tag.len() > 40 || tag.chars().any(char::is_control))
    {
        return Err(AppError::Invalid(
            "tags must be 1-40 printable characters".into(),
        ));
    }
    let transaction = connection.transaction()?;
    if !transaction
        .query_row("SELECT 1 FROM nodes WHERE id=?1", [node_id], |_| Ok(true))
        .optional()?
        .unwrap_or(false)
    {
        return Err(AppError::NotFound(format!("node {node_id}")));
    }
    transaction.execute("DELETE FROM node_tags WHERE node_id=?1", [node_id])?;
    for tag in cleaned {
        transaction.execute(
            "INSERT INTO tags(name,color) VALUES(?1,'#4dd8ff') ON CONFLICT(name) DO NOTHING",
            [tag],
        )?;
        transaction.execute(
            "INSERT INTO node_tags(node_id,tag_id) SELECT ?1,id FROM tags WHERE name=?2",
            params![node_id, tag],
        )?;
    }
    transaction.execute("DELETE FROM notes WHERE node_id=?1", [node_id])?;
    if let Some(body) = notes.map(str::trim).filter(|body| !body.is_empty()) {
        if body.len() > 20_000 {
            return Err(AppError::Invalid(
                "notes cannot exceed 20,000 characters".into(),
            ));
        }
        transaction.execute(
            "INSERT INTO notes(node_id,body) VALUES(?1,?2)",
            params![node_id, body],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_and_upserts_aggregate_flows() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(SCHEMA).unwrap();
        start_import(&connection, "one", "csv", "test.csv").unwrap();
        let flow = FlowRecord {
            source_ip: "10.0.0.1".into(),
            destination_ip: "10.0.0.2".into(),
            source_port: Some(10),
            destination_port: Some(443),
            protocol: "TCP".into(),
            bytes: 100,
            packets: 1,
            timestamp: Some(1),
        };
        insert_batch(&mut connection, "one", &[flow.clone(), flow]).unwrap();
        finish_import(&connection, "one", 2, 0, "complete", None).unwrap();
        let result = query_graph(&connection, &GraphFilters::default()).unwrap();
        assert_eq!(result.edges[0].bytes, 200);
        assert_eq!(result.nodes.len(), 2);

        let node_id = result.nodes[0].id;
        set_node_metadata(
            &mut connection,
            node_id,
            &["critical".into(), "server".into()],
            Some("Reviewed offline"),
        )
        .unwrap();
        let result = query_graph(&connection, &GraphFilters::default()).unwrap();
        let changed = result.nodes.iter().find(|node| node.id == node_id).unwrap();
        assert_eq!(changed.tags, vec!["critical", "server"]);
        assert_eq!(changed.notes.as_deref(), Some("Reviewed offline"));

        let state = serde_json::json!({"layout": "circle", "filters": {"query": "10.0.0.1"}});
        save_view(&connection, "view-one", "Investigate host", &state).unwrap();
        let views = list_views(&connection).unwrap();
        assert_eq!(views[0].name, "Investigate host");
        assert_eq!(views[0].state, state);
    }
}
