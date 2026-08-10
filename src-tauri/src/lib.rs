mod commands;
mod csv_import;
mod db;
mod error;
mod live_capture;
mod models;
mod pcap_import;
mod storage;
mod vendor;

use commands::AppState;

fn configure_portable_webview_runtime() {
    if cfg!(debug_assertions) || std::env::var_os("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER").is_some() {
        return;
    }
    if let Ok(executable) = std::env::current_exe() {
        if let Some(directory) = executable.parent() {
            let root = directory.join("WebView2.FixedVersionRuntime");
            let runtime = if root.join("msedgewebview2.exe").is_file() {
                Some(root)
            } else {
                std::fs::read_dir(&root).ok().and_then(|entries| {
                    entries
                        .flatten()
                        .map(|entry| entry.path())
                        .find(|path| path.join("msedgewebview2.exe").is_file())
                })
            };
            if let Some(runtime) = runtime {
                std::env::set_var("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER", runtime);
            }
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    configure_portable_webview_runtime();
    let storage = storage::Storage::discover().expect("failed to initialize portable data storage");
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::new(storage))
        .invoke_handler(tauri::generate_handler![
            commands::diagnostics,
            commands::create_project,
            commands::open_project,
            commands::list_projects,
            commands::list_test_pcaps,
            commands::rename_project,
            commands::preview_csv,
            commands::import_csv,
            commands::import_pcap,
            commands::cancel_import,
            commands::query_graph,
            commands::query_packets,
            commands::delete_import,
            commands::retain_imports,
            commands::save_view,
            commands::list_views,
            commands::set_node_metadata,
            commands::export_filtered_csv,
            commands::list_capture_interfaces,
            commands::start_live_capture,
            commands::stop_live_capture,
            commands::live_capture_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running NetMap Portable");
}
