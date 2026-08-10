use crate::csv_import;
use crate::db;
use crate::error::{require_existing_file, AppError, Result};
use crate::live_capture::{self, LiveSession};
use crate::models::{
    CaptureInterfacesResponse, CsvMapping, CsvPreview, Diagnostics, GraphFilters, GraphResult,
    ImportProgress, ImportResult, LiveCaptureSession, LiveCaptureUpdate, ProjectInfo,
    PacketPage, PcapImportOptions, SavedViewRecord, TestCapture,
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
    live_session: Arc<Mutex<Option<LiveSession>>>,
}

impl AppState {
    pub fn new(storage: Storage) -> Self {
        Self {
            storage,
            cancellations: Arc::new(Mutex::new(HashMap::new())),
            live_session: Arc::new(Mutex::new(None)),
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
pub fn list_test_pcaps(state: State<'_, AppState>) -> Result<Vec<TestCapture>> {
    state.storage.list_test_captures()
}

#[tauri::command]
pub fn rename_project(
    project_id: String,
    name: String,
    state: State<'_, AppState>,
) -> Result<ProjectInfo> {
    state.storage.rename_project(&project_id, &name)
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
    options: Option<PcapImportOptions>,
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
            pcap_import::import(&mut connection, &path, id, token.as_ref(), &options.unwrap_or_default(), progress)
        },
    )
    .await
}

#[tauri::command]
pub async fn query_packets(
    project_id: String,
    limit: Option<u32>,
    offset: Option<u64>,
    search: Option<String>,
    state: State<'_, AppState>,
) -> Result<PacketPage> {
    let database = state.storage.database_path(&project_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let connection = db::open(&database)?;
        db::query_packets(&connection, limit.unwrap_or(250), offset.unwrap_or(0), search.as_deref())
    })
    .await
    .map_err(|error| AppError::Invalid(format!("packet query worker failed: {error}")))?
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
pub async fn retain_imports(
    project_id: String,
    import_ids: Vec<String>,
    state: State<'_, AppState>,
) -> Result<()> {
    let database = state.storage.database_path(&project_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let mut connection = db::open(&database)?;
        db::retain_imports(&mut connection, &import_ids)
    })
    .await
    .map_err(|error| AppError::Invalid(format!("replace import worker failed: {error}")))?
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
    asset_role: Option<String>,
    security_zone: Option<String>,
    state: State<'_, AppState>,
) -> Result<()> {
    let database = state.storage.database_path(&project_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let mut connection = db::open(&database)?;
        db::set_node_metadata(
            &mut connection,
            node_id,
            &tags,
            notes.as_deref(),
            asset_role.as_deref(),
            security_zone.as_deref(),
        )
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

fn request_stop_live(live_session: &Mutex<Option<LiveSession>>) -> Result<bool> {
    let guard = live_session
        .lock()
        .map_err(|_| AppError::Invalid("live session registry is unavailable".into()))?;
    if let Some(session) = guard.as_ref() {
        session.cancel.store(true, Ordering::Relaxed);
        if let Ok(mut child) = session.child.lock() {
            if let Some(process) = child.as_mut() {
                let _ = process.kill();
            }
        }
        Ok(true)
    } else {
        Ok(false)
    }
}

#[tauri::command]
pub fn list_capture_interfaces() -> Result<CaptureInterfacesResponse> {
    live_capture::list_interfaces()
}

#[tauri::command]
pub fn live_capture_status(state: State<'_, AppState>) -> Result<Option<LiveCaptureSession>> {
    let guard = state
        .live_session
        .lock()
        .map_err(|_| AppError::Invalid("live session registry is unavailable".into()))?;
    Ok(guard.as_ref().map(|session| LiveCaptureSession {
        session_id: session.session_id.clone(),
        import_id: session.import_id.clone(),
        interface_id: session.interface_id.clone(),
        interface_name: session.interface_name.clone(),
        status: if session.cancel.load(Ordering::Relaxed) {
            "stopping".into()
        } else {
            "capturing".into()
        },
    }))
}

#[tauri::command]
pub fn stop_live_capture(state: State<'_, AppState>) -> Result<bool> {
    request_stop_live(&state.live_session)
}

#[tauri::command]
pub async fn start_live_capture(
    app: AppHandle,
    project_id: String,
    interface_id: String,
    bpf_filter: Option<String>,
    state: State<'_, AppState>,
) -> Result<LiveCaptureSession> {
    let _ = request_stop_live(&state.live_session)?;
    // Give a previous worker a moment to release the NIC / DB row.
    std::thread::sleep(std::time::Duration::from_millis(150));

    let tshark = live_capture::find_tshark().ok_or_else(|| {
        AppError::Invalid("tshark not found. Install Wireshark (includes tshark) and Npcap.".into())
    })?;
    let listed = live_capture::list_interfaces()?;
    let interface = live_capture::validate_interface_id(&interface_id, &listed.interfaces)?;
    let bpf = live_capture::validate_bpf(bpf_filter.as_deref().unwrap_or(""))?;

    let database = state.storage.database_path(&project_id)?;
    let session_id = Uuid::new_v4().to_string();
    let import_id = session_id.clone();
    let cancel = Arc::new(AtomicBool::new(false));
    let child_slot = Arc::new(Mutex::new(None));

    {
        let connection = db::open(&database)?;
        db::start_import(
            &connection,
            &import_id,
            "pcap",
            &format!("live:{}", interface.name),
        )?;
    }

    let mut child = live_capture::spawn_tshark(&tshark, &interface.id, bpf.as_deref())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AppError::Invalid("tshark stdout was not captured".into()))?;
    {
        let mut slot = child_slot
            .lock()
            .map_err(|_| AppError::Invalid("live child lock failed".into()))?;
        *slot = Some(child);
    }

    let session = LiveSession {
        session_id: session_id.clone(),
        import_id: import_id.clone(),
        interface_id: interface.id.clone(),
        interface_name: interface.name.clone(),
        cancel: cancel.clone(),
        child: child_slot.clone(),
    };
    {
        let mut guard = state
            .live_session
            .lock()
            .map_err(|_| AppError::Invalid("live session registry is unavailable".into()))?;
        *guard = Some(session);
    }

    state
        .cancellations
        .lock()
        .map_err(|_| AppError::Invalid("cancellation registry is unavailable".into()))?
        .insert(import_id.clone(), cancel.clone());

    let live_registry = state.live_session.clone();
    let cancel_registry = state.cancellations.clone();
    let worker_session = session_id.clone();
    let worker_import = import_id.clone();
    let worker_app = app.clone();

    let _ = app.emit(
        "live-capture-update",
        LiveCaptureUpdate {
            session_id: session_id.clone(),
            import_id: import_id.clone(),
            status: "starting".into(),
            packets: 0,
            accepted: 0,
            skipped: 0,
            message: Some(format!("Capturing on {}", interface.name)),
            dataset: None,
        },
    );

    tauri::async_runtime::spawn_blocking(move || {
        let emit_app = worker_app.clone();
        let result = (|| {
            let mut connection = db::open(&database)?;
            live_capture::run_capture_loop(
                &mut connection,
                &worker_import,
                &worker_session,
                stdout,
                cancel.as_ref(),
                child_slot,
                |update| {
                    let _ = emit_app.emit("live-capture-update", update);
                },
            )
        })();

        if let Err(error) = &result {
            if let Ok(connection) = db::open(&database) {
                let _ = db::finish_import(
                    &connection,
                    &worker_import,
                    0,
                    0,
                    "failed",
                    Some(&error.to_string()),
                );
            }
            let _ = worker_app.emit(
                "live-capture-update",
                LiveCaptureUpdate {
                    session_id: worker_session.clone(),
                    import_id: worker_import.clone(),
                    status: "failed".into(),
                    packets: 0,
                    accepted: 0,
                    skipped: 0,
                    message: Some(error.to_string()),
                    dataset: None,
                },
            );
        }

        if let Ok(mut guard) = live_registry.lock() {
            if guard
                .as_ref()
                .is_some_and(|session| session.session_id == worker_session)
            {
                *guard = None;
            }
        }
        if let Ok(mut registry) = cancel_registry.lock() {
            registry.remove(&worker_import);
        }
    });

    Ok(LiveCaptureSession {
        session_id,
        import_id,
        interface_id: interface.id,
        interface_name: interface.name,
        status: "capturing".into(),
    })
}
