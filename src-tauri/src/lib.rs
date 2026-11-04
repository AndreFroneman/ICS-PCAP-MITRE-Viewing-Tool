mod capture;
mod case;
mod correlate;
mod suricata;
mod tshark;

use std::path::PathBuf;

use tauri::{Emitter, Manager};

fn service() -> &'static str {
    "Primer"
}

fn engine_dirs(app: &tauri::AppHandle) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(resource) = app.path().resource_dir() {
        dirs.push(resource.join("engines"));
        dirs.push(resource.join("resources").join("engines"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            dirs.push(dir.join("engines"));
        }
    }
    dirs
}

#[tauri::command]
fn key_set(provider: String, secret: String) -> Result<(), String> {
    let entry = keyring::Entry::new(service(), &provider).map_err(|err| err.to_string())?;
    entry.set_password(&secret).map_err(|err| err.to_string())
}

#[tauri::command]
fn key_get(provider: String) -> Result<String, String> {
    let entry = keyring::Entry::new(service(), &provider).map_err(|err| err.to_string())?;
    match entry.get_password() {
        Ok(value) => Ok(value),
        Err(keyring::Error::NoEntry) => Ok(String::new()),
        Err(err) => Err(err.to_string()),
    }
}

#[tauri::command]
fn key_delete(provider: String) -> Result<(), String> {
    let entry = keyring::Entry::new(service(), &provider).map_err(|err| err.to_string())?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(err) => Err(err.to_string()),
    }
}

#[tauri::command]
fn default_capture_folder() -> String {
    "C:\\Virtual Share\\Pcap".to_string()
}

#[tauri::command]
fn list_captures(dir: String) -> Result<Vec<String>, String> {
    let mut found = Vec::new();
    let entries = std::fs::read_dir(&dir).map_err(|err| err.to_string())?;
    for entry in entries {
        let entry = entry.map_err(|err| err.to_string())?;
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".pcap") || lower.ends_with(".pcapng") || lower.ends_with(".cap") || lower.ends_with(".dmp") || lower.ends_with(".gz") {
            found.push(path.to_string_lossy().to_string());
        }
    }
    found.sort();
    Ok(found)
}

/// Whole-file read kept for modest captures. Large files should use the case copy and `read_span`.
#[tauri::command]
fn read_capture(path: String) -> Result<tauri::ipc::Response, String> {
    let bytes = std::fs::read(PathBuf::from(path)).map_err(|err| err.to_string())?;
    Ok(tauri::ipc::Response::new(bytes))
}

#[tauri::command]
fn startup_capture() -> Option<String> {
    std::env::args().find(|arg| {
        let lower = arg.to_ascii_lowercase();
        lower.ends_with(".pcap") || lower.ends_with(".pcapng") || lower.ends_with(".cap") || lower.ends_with(".gz") || lower.ends_with(".dmp")
    })
}

#[tauri::command]
fn cases_root() -> String {
    case::cases_root().display().to_string()
}

#[tauri::command]
fn import_evidence(path: String, name: String, investigator: String) -> Result<case::Imported, String> {
    case::import_evidence(PathBuf::from(path).as_path(), &name, &investigator)
}

#[tauri::command]
fn verify_evidence(case_id: String) -> Result<bool, String> {
    case::verify_evidence(&case_id)
}

#[tauri::command]
fn save_packet_index(case_id: String, evidence_id: String, rows: Vec<case::IndexIn>) -> Result<(), String> {
    case::save_index(&case_id, &evidence_id, &rows)
}

#[tauri::command]
fn save_packets(case_id: String, evidence_id: String, engine: String, rows: Vec<case::PacketIn>) -> Result<(), String> {
    case::save_packets(&case_id, &evidence_id, &engine, &rows)
}

#[tauri::command]
fn save_findings(case_id: String, evidence_id: String, findings: Vec<case::FindingIn>) -> Result<(), String> {
    case::save_findings(&case_id, &evidence_id, &findings, &["primer", "correlation"])
}

#[tauri::command]
fn list_findings(case_id: String) -> Result<Vec<case::FindingIn>, String> {
    case::list_findings(&case_id)
}

#[tauri::command]
fn save_assets(case_id: String, evidence_id: String, assets: Vec<serde_json::Value>) -> Result<(), String> {
    case::save_assets(&case_id, &evidence_id, &assets)
}

#[tauri::command]
fn save_fingerprints(case_id: String, evidence_id: String, rows: Vec<serde_json::Value>) -> Result<(), String> {
    case::save_fingerprints(&case_id, &evidence_id, &rows)
}

#[tauri::command]
fn set_validation(case_id: String, finding_id: String, validation: String, actor: String, note: String) -> Result<(), String> {
    case::set_validation(&case_id, &finding_id, &validation, &actor, &note)
}

#[tauri::command]
fn add_note(case_id: String, finding_id: String, body: String, author: String) -> Result<(), String> {
    case::add_note(&case_id, &finding_id, &body, &author)
}

#[tauri::command]
fn activity(case_id: String) -> Result<Vec<serde_json::Value>, String> {
    case::activity(&case_id)
}

#[tauri::command]
fn list_cases() -> Result<Vec<serde_json::Value>, String> {
    case::list_cases()
}

#[tauri::command]
fn read_span(path: String, offset: u64, len: u64) -> Result<tauri::ipc::Response, String> {
    let bytes = case::read_span(PathBuf::from(path).as_path(), offset, len)?;
    Ok(tauri::ipc::Response::new(bytes))
}

#[tauri::command]
fn engine_status(app: tauri::AppHandle) -> serde_json::Value {
    let dirs = engine_dirs(&app);
    let tshark = tshark::locate_tshark(&dirs);
    let suricata = suricata::status(&dirs);
    let capture = capture::status(&dirs);
    serde_json::json!({
        "tsharkPath": tshark.map(|p| p.display().to_string()).unwrap_or_default(),
        "tsharkVersion": "4.6.9",
        "suricata": suricata,
        "capture": capture,
        "about": "TShark, when bundled, is a separate unmodified program. Primer does not link libwireshark. Suricata is not bundled. See THIRD_PARTY_NOTICES.md.",
    })
}

#[tauri::command]
fn run_engines(app: tauri::AppHandle, case_id: String, evidence_id: String, stored_path: String) -> Result<(), String> {
    let dirs = engine_dirs(&app);
    std::thread::spawn(move || {
        let _ = app.emit("engine-progress", serde_json::json!({"engine": "tshark", "state": "start"}));
        if let Some(bin) = tshark::locate_tshark(&dirs) {
            match tshark::run_tshark(&bin, PathBuf::from(&stored_path).as_path(), &case_id, &evidence_id) {
                Ok(detail) => { let _ = app.emit("engine-progress", serde_json::json!({"engine": "tshark", "state": "done", "detail": detail})); }
                Err(detail) => { let _ = app.emit("engine-progress", serde_json::json!({"engine": "tshark", "state": "error", "detail": detail})); }
            }
        } else {
            let _ = app.emit("engine-progress", serde_json::json!({"engine": "tshark", "state": "absent", "detail": "TShark is not installed next to Primer. The in-house decoder is still the packet list."}));
        }
        let _ = app.emit("engine-progress", serde_json::json!({"engine": "suricata", "state": "start"}));
        if let Some(bin) = suricata::locate_suricata(&dirs) {
            let config = dirs.iter().map(|d| d.join("..").join("suricata").join("suricata.yaml")).find(|p| p.is_file())
                .or_else(|| dirs.iter().map(|d| d.join("suricata.yaml")).find(|p| p.is_file()));
            if let Some(config) = config {
                match suricata::run_suricata(&bin, PathBuf::from(&stored_path).as_path(), &case_id, &evidence_id, &config) {
                    Ok(detail) => {
                        let _ = correlate::correlate_case(&case_id);
                        let _ = app.emit("engine-progress", serde_json::json!({"engine": "suricata", "state": "done", "detail": detail}));
                    }
                    Err(detail) => { let _ = app.emit("engine-progress", serde_json::json!({"engine": "suricata", "state": "error", "detail": detail})); }
                }
            } else {
                let _ = app.emit("engine-progress", serde_json::json!({"engine": "suricata", "state": "error", "detail": "suricata.yaml was not found next to the program."}));
            }
        } else {
            let _ = app.emit("engine-progress", serde_json::json!({"engine": "suricata", "state": "absent", "detail": suricata::NOT_BUNDLED}));
        }
        let _ = app.emit("engine-progress", serde_json::json!({"engine": "case", "state": "done"}));
    });
    Ok(())
}

#[tauri::command]
fn tshark_frame(app: tauri::AppHandle, path: String, n: u64) -> Result<String, String> {
    let bin = tshark::locate_tshark(&engine_dirs(&app)).ok_or_else(|| "TShark is not available. Primer's own decode is still shown.".to_string())?;
    tshark::frame_verbose(&bin, PathBuf::from(path).as_path(), n)
}

#[tauri::command]
fn capture_status(app: tauri::AppHandle) -> capture::CaptureStatus {
    capture::status(&engine_dirs(&app))
}

#[tauri::command]
fn list_interfaces(app: tauri::AppHandle) -> Result<Vec<String>, String> {
    let status = capture::status(&engine_dirs(&app));
    if !status.available {
        return Err(status.message);
    }
    let dumpcap = capture::locate_dumpcap(&engine_dirs(&app)).ok_or_else(|| status.message.clone())?;
    capture::list_interfaces(&dumpcap)
}

#[tauri::command]
fn start_live_capture(app: tauri::AppHandle, iface: String, seconds: u64) -> Result<String, String> {
    let status = capture::status(&engine_dirs(&app));
    if !status.available {
        return Err(status.message);
    }
    let dumpcap = capture::locate_dumpcap(&engine_dirs(&app)).ok_or_else(|| status.message)?;
    let dest = case::cases_root().join("inbox").join(format!("live-{}.pcapng", case::now_iso().replace(':', "-")));
    capture::start_capture(&dumpcap, &iface, seconds, &dest)?;
    Ok(dest.display().to_string())
}

#[tauri::command]
fn stop_live_capture() -> Result<String, String> {
    capture::stop_capture()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_http::init())
        .invoke_handler(tauri::generate_handler![
            key_set,
            key_get,
            key_delete,
            default_capture_folder,
            list_captures,
            read_capture,
            startup_capture,
            cases_root,
            import_evidence,
            verify_evidence,
            save_packet_index,
            save_packets,
            save_findings,
            list_findings,
            save_assets,
            save_fingerprints,
            set_validation,
            add_note,
            activity,
            list_cases,
            read_span,
            engine_status,
            run_engines,
            tshark_frame,
            capture_status,
            list_interfaces,
            start_live_capture,
            stop_live_capture
        ])
        .run(tauri::generate_context!())
        .expect("error while running Primer");
}
