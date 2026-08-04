use crate::csv_import;
use crate::db;
use crate::error::{require_existing_file, AppError, Result};
use crate::models::{
    CsvMapping, CsvPreview, Diagnostics, GraphFilters, GraphResult, ImportProgress, ImportResult,
    ProjectInfo, SavedViewRecord,
};
use crate::pcap_import;
use crate::storage::Storage;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, State};
use uuid::Uuid;

pub struct AppState {
    pub storage: Storage,
    cancellations: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
}

impl AppState {
    pub fn new(storage: Storage) -> Self {
        Self {
            storage,
            cancellations: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[tauri::command]
pub fn diagnostics(state: State<'_, AppState>) -> Result<Diagnostics> {
    Ok(Diagnostics {
        version: env!("CARGO_PKG_VERSION").into(),
        data_root: state.storage.root().display().to_string(),
        portable_mode: state.storage.is_portable(),
        sqlite_version: rusqlite::version().into(),
    })
}

#[tauri::command]
pub fn create_project(name: String, state: State<'_, AppState>) -> Result<ProjectInfo> {
    state.storage.create_project(&name)
}

#[tauri::command]
pub fn open_project(project_id: String, state: State<'_, AppState>) -> Result<ProjectInfo> {
    state.storage.open_project(&project_id)
}

#[tauri::command]
pub fn list_projects(state: State<'_, AppState>) -> Result<Vec<ProjectInfo>> {
    state.storage.list_projects()
}

#[tauri::command]
pub async fn preview_csv(path: String) -> Result<CsvPreview> {
    let path = require_existing_file(&path, &["csv", "tsv"])?;
    tauri::async_runtime::spawn_blocking(move || csv_import::preview(&path))
        .await
        .map_err(|error| AppError::Invalid(format!("preview worker failed: {error}")))?
}

#[tauri::command]
pub async fn import_csv(
    app: AppHandle,
    project_id: String,
    path: String,
    mapping: Option<CsvMapping>,
    state: State<'_, AppState>,
) -> Result<ImportResult> {
    let path = require_existing_file(&path, &["csv", "tsv"])?;
    let database = state.storage.database_path(&project_id)?;
    let import_id = Uuid::new_v4().to_string();
    run_import(
        app,
        import_id,
        state.cancellations.clone(),
        move |token, id, progress| {
            let mut connection = db::open(&database)?;
            csv_import::import(
                &mut connection,
                &path,
                id,
                mapping,
                token.as_ref(),
                progress,
            )
        },
    )
    .await
}

#[tauri::command]
pub async fn import_pcap(
    app: AppHandle,
    project_id: String,
    path: String,
    state: State<'_, AppState>,
) -> Result<ImportResult> {
    let path = require_existing_file(&path, &["pcap", "pcapng"])?;
    let database = state.storage.database_path(&project_id)?;
    let import_id = Uuid::new_v4().to_string();
    run_import(
        app,
        import_id,
        state.cancellations.clone(),
        move |token, id, progress| {
            let mut connection = db::open(&database)?;
            pcap_import::import(&mut connection, &path, id, token.as_ref(), progress)
        },
    )
    .await
}

async fn run_import<F>(
    app: AppHandle,
    import_id: String,
    cancellations: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
    worker: F,
) -> Result<ImportResult>
where
    F: FnOnce(Arc<AtomicBool>, &str, Box<dyn FnMut(ImportProgress) + Send>) -> Result<ImportResult>
        + Send
        + 'static,
{
    let token = Arc::new(AtomicBool::new(false));
    let _ = app.emit(
        "import-progress",
        ImportProgress {
            import_id: import_id.clone(),
            phase: "starting".into(),
            processed: 0,
            accepted: 0,
            skipped: 0,
            total_bytes: None,
            completed: false,
            cancelled: false,
            message: None,
        },
    );
    cancellations
        .lock()
        .map_err(|_| AppError::Invalid("cancellation registry is unavailable".into()))?
        .insert(import_id.clone(), token.clone());
    let worker_id = import_id.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let event_app = app.clone();
        let progress: Box<dyn FnMut(ImportProgress) + Send> = Box::new(move |event| {
            let _ = event_app.emit("import-progress", event);
        });
        worker(token, &worker_id, progress)
    })
    .await
    .map_err(|error| AppError::Invalid(format!("import worker failed: {error}")))?;
    if let Ok(mut registry) = cancellations.lock() {
        registry.remove(&import_id);
    }
    result
}

#[tauri::command]
pub fn cancel_import(import_id: String, state: State<'_, AppState>) -> Result<bool> {
    let registry = state
        .cancellations
        .lock()
        .map_err(|_| AppError::Invalid("cancellation registry is unavailable".into()))?;
    if let Some(token) = registry.get(&import_id) {
        token.store(true, Ordering::Relaxed);
        Ok(true)
    } else {
        Ok(false)
    }
}

#[tauri::command]
pub async fn query_graph(
    project_id: String,
    filters: GraphFilters,
    state: State<'_, AppState>,
) -> Result<GraphResult> {
    let database = state.storage.database_path(&project_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let connection = db::open(&database)?;
        db::query_graph(&connection, &filters)
    })
    .await
    .map_err(|error| AppError::Invalid(format!("query worker failed: {error}")))?
}

#[tauri::command]
pub async fn delete_import(
    project_id: String,
    import_id: String,
    state: State<'_, AppState>,
) -> Result<()> {
    let database = state.storage.database_path(&project_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let mut connection = db::open(&database)?;
        db::delete_import(&mut connection, &import_id)
    })
    .await
    .map_err(|error| AppError::Invalid(format!("delete worker failed: {error}")))?
}

#[tauri::command]
pub async fn save_view(
    project_id: String,
    view_id: Option<String>,
    name: String,
    state_json: serde_json::Value,
    state: State<'_, AppState>,
) -> Result<String> {
    let database = state.storage.database_path(&project_id)?;
    let id = view_id.unwrap_or_else(|| Uuid::new_v4().to_string());
    let saved_id = id.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let connection = db::open(&database)?;
        db::save_view(&connection, &saved_id, &name, &state_json)
    })
    .await
    .map_err(|error| AppError::Invalid(format!("save worker failed: {error}")))??;
    Ok(id)
}

#[tauri::command]
pub async fn list_views(
    project_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<SavedViewRecord>> {
    let database = state.storage.database_path(&project_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let connection = db::open(&database)?;
        db::list_views(&connection)
    })
    .await
    .map_err(|error| AppError::Invalid(format!("view query worker failed: {error}")))?
}

#[tauri::command]
pub async fn set_node_metadata(
    project_id: String,
    node_id: i64,
    tags: Vec<String>,
    notes: Option<String>,
    state: State<'_, AppState>,
) -> Result<()> {
    let database = state.storage.database_path(&project_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let mut connection = db::open(&database)?;
        db::set_node_metadata(&mut connection, node_id, &tags, notes.as_deref())
    })
    .await
    .map_err(|error| AppError::Invalid(format!("metadata worker failed: {error}")))?
}

#[tauri::command]
pub async fn export_filtered_csv(
    project_id: String,
    filename: String,
    filters: GraphFilters,
    state: State<'_, AppState>,
) -> Result<String> {
    let database = state.storage.database_path(&project_id)?;
    let output = state.storage.export_path(&project_id, &filename)?;
    let output_string = output.display().to_string();
    tauri::async_runtime::spawn_blocking(move || {
        let connection = db::open(&database)?;
        let graph = db::query_graph(&connection, &filters)?;
        let nodes = graph
            .nodes
            .iter()
            .map(|node| (node.id, node.ip.as_str()))
            .collect::<HashMap<_, _>>();
        let temporary = output.with_extension("csv.tmp");
        {
            let mut writer = csv::Writer::from_path(&temporary)?;
            writer.write_record([
                "source_ip",
                "destination_ip",
                "source_port",
                "destination_port",
                "protocol",
                "bytes",
                "packets",
                "first_seen",
                "last_seen",
            ])?;
            for edge in graph.edges {
                writer.write_record([
                    nodes
                        .get(&edge.source)
                        .copied()
                        .unwrap_or_default()
                        .to_string(),
                    nodes
                        .get(&edge.target)
                        .copied()
                        .unwrap_or_default()
                        .to_string(),
                    edge.source_port
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                    edge.destination_port
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                    edge.protocol,
                    edge.bytes.to_string(),
                    edge.packets.to_string(),
                    edge.first_seen
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                    edge.last_seen
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                ])?;
            }
            writer.flush()?;
        }
        std::fs::rename(temporary, output)?;
        Ok::<_, AppError>(())
    })
    .await
    .map_err(|error| AppError::Invalid(format!("export worker failed: {error}")))??;
    Ok(output_string)
}
