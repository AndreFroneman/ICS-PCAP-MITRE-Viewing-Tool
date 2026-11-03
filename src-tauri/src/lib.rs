use std::path::PathBuf;

fn service() -> &'static str {
    "Primer"
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
    if cfg!(windows) {
        "C:\\Virtual Share\\Pcap".to_string()
    } else {
        "C:\\Virtual Share\\Pcap".to_string()
    }
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

#[tauri::command]
fn read_capture(path: String) -> Result<Vec<u8>, String> {
    std::fs::read(PathBuf::from(path)).map_err(|err| err.to_string())
}

#[tauri::command]
fn startup_capture() -> Option<String> {
    std::env::args().find(|arg| {
        let lower = arg.to_ascii_lowercase();
        lower.ends_with(".pcap") || lower.ends_with(".pcapng") || lower.ends_with(".cap") || lower.ends_with(".gz") || lower.ends_with(".dmp")
    })
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
            startup_capture
        ])
        .run(tauri::generate_context!())
        .expect("error while running Primer");
}
