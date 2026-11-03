use std::path::{PathBuf, Path};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use crate::tshark::which;

static LIVE: Mutex<Option<Child>> = Mutex::new(None);

pub const NPCAP_URL: &str = "https://npcap.com/#download";

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureStatus {
    pub available: bool,
    pub npcap: bool,
    pub dumpcap: String,
    pub message: String,
    pub url: String,
}

fn npcap_present() -> bool {
    if !cfg!(windows) {
        return false;
    }
    Path::new(r"C:\Windows\System32\Npcap\wpcap.dll").is_file()
        || Path::new(r"C:\Windows\SysWOW64\Npcap\wpcap.dll").is_file()
}

pub fn locate_dumpcap(extra: &[PathBuf]) -> Option<PathBuf> {
    for dir in extra {
        for name in ["dumpcap.exe", "dumpcap"] {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    which(if cfg!(windows) { "dumpcap.exe" } else { "dumpcap" }).or_else(|| {
        if cfg!(windows) {
            let program_files = std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into());
            let candidate = PathBuf::from(program_files).join("Wireshark").join("dumpcap.exe");
            candidate.is_file().then_some(candidate)
        } else {
            None
        }
    })
}

pub fn status(extra: &[PathBuf]) -> CaptureStatus {
    let dumpcap = locate_dumpcap(extra);
    let npcap = npcap_present();
    if cfg!(windows) && !npcap {
        return CaptureStatus {
            available: false,
            npcap: false,
            dumpcap: dumpcap.map(|p| p.display().to_string()).unwrap_or_default(),
            message: format!("Npcap is not installed, so Primer cannot record from a network interface. Primer does not bundle Npcap: the free Npcap licence does not allow that. Install it yourself from {NPCAP_URL} if you want live capture. Installing it may ask for an administrator, and capturing may ask again. Opening a saved capture never needs Npcap or an administrator."),
            url: NPCAP_URL.into(),
        };
    }
    match dumpcap {
        Some(path) => CaptureStatus {
            available: true,
            npcap: npcap || !cfg!(windows),
            dumpcap: path.display().to_string(),
            message: "Live capture is optional and separate from offline analysis. On Windows, Npcap may require an administrator to install and may require permission to capture. The recording is written to a pcapng and then opened like any other case. Offline analysis does not use this.".into(),
            url: NPCAP_URL.into(),
        },
        None => CaptureStatus {
            available: false,
            npcap,
            dumpcap: String::new(),
            message: "Dumpcap was not found, so there is nothing to record with. Offline analysis does not need it. A Primer installer that bundled TShark includes dumpcap for this optional step.".into(),
            url: NPCAP_URL.into(),
        },
    }
}

pub fn list_interfaces(dumpcap: &Path) -> Result<Vec<String>, String> {
    let output = Command::new(dumpcap).arg("-D").output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<String> = text.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
    if lines.is_empty() {
        return Err("Dumpcap did not list any interfaces. On Windows that usually means Npcap is missing or this user is not allowed to capture.".into());
    }
    Ok(lines)
}

pub fn start_capture(dumpcap: &Path, iface: &str, seconds: u64, dest: &Path) -> Result<(), String> {
    if iface.trim().is_empty() || iface.contains('\n') || iface.contains('\0') {
        return Err("Choose an interface from the list.".into());
    }
    let seconds = seconds.clamp(5, 3600);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut guard = LIVE.lock().map_err(|e| e.to_string())?;
    if guard.is_some() {
        return Err("A capture is already running. Stop it before starting another.".into());
    }
    let child = Command::new(dumpcap)
        .arg("-i").arg(iface)
        .arg("-w").arg(dest)
        .arg("-a").arg(format!("duration:{seconds}"))
        .arg("-q")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Could not start dumpcap: {e}"))?;
    *guard = Some(child);
    Ok(())
}

pub fn stop_capture() -> Result<String, String> {
    let mut guard = LIVE.lock().map_err(|e| e.to_string())?;
    let Some(mut child) = guard.take() else {
        return Ok("No capture was running.".into());
    };
    let _ = child.kill();
    let _ = child.wait();
    Ok("Capture stopped. Open the pcapng as a case. It is ordinary evidence from here.".into())
}
