fn main() {
    // tauri-build requires a Windows resource icon even when bundle.icon is empty.
    // Keep this tiny neutral icon in OUT_DIR so the backend remains self-contained.
    let icon = [
        0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 32, 0, 48, 0, 0, 0, 22, 0, 0, 0, 40, 0, 0, 0, 1, 0, 0,
        0, 2, 0, 0, 0, 1, 0, 32, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 128, 255, 255, 0, 0, 0, 0,
    ];
    let icon_path = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("icons")
        .join("icon.ico");
    std::fs::create_dir_all(icon_path.parent().unwrap()).expect("failed to create icon directory");
    if !icon_path.exists() {
        std::fs::write(&icon_path, icon).expect("failed to create Windows resource icon");
    }
    let commands = &[
        "diagnostics",
        "create_project",
        "open_project",
        "list_projects",
        "list_test_pcaps",
        "rename_project",
        "preview_csv",
        "import_csv",
        "import_pcap",
        "cancel_import",
        "query_graph",
        "delete_import",
        "retain_imports",
        "save_view",
        "list_views",
        "set_node_metadata",
        "export_filtered_csv",
        "list_capture_interfaces",
        "start_live_capture",
        "stop_live_capture",
        "live_capture_status",
    ];
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(commands))
            .windows_attributes(tauri_build::WindowsAttributes::new().window_icon_path(icon_path)),
    )
    .expect("failed to build Tauri application");
}
