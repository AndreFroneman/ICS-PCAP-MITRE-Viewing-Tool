use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use crate::case::{self, PacketIn};

/// Fixed field list. A full `-V` tree is fetched only for the frame on screen.
pub const FIELDS: &[&str] = &[
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "_ws.col.Protocol",
    "_ws.col.Info",
    "modbus.func_code",
    "modbus.reference_num",
    "s7comm.param.func",
    "dnp3.al.func",
    "cip.service",
    "tls.handshake.ja3",
    "http.user_agent",
    "smb2.dialect",
    "rdp.client.keyboard_layout",
];

pub fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

pub fn locate_tshark(extra: &[PathBuf]) -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PRIMER_TSHARK") {
        let candidate = PathBuf::from(path);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    for dir in extra {
        for name in ["tshark.exe", "tshark"] {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    which(if cfg!(windows) { "tshark.exe" } else { "tshark" }).or_else(|| {
        if cfg!(windows) {
            let program_files = std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into());
            let candidate = PathBuf::from(program_files).join("Wireshark").join("tshark.exe");
            if candidate.is_file() { Some(candidate) } else { None }
        } else {
            None
        }
    })
}

fn text_of(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Array(items) => items.first().map(text_of).unwrap_or_default(),
        _ => String::new(),
    }
}

fn layers_of(entry: &Value) -> Option<&serde_json::Map<String, Value>> {
    entry.get("_source").and_then(|s| s.get("layers")).and_then(|l| l.as_object())
        .or_else(|| entry.get("layers").and_then(|l| l.as_object()))
        .or_else(|| entry.as_object())
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TsharkExtra {
    pub n: i64,
    pub ja3: String,
    pub rdp_keyboard: String,
    pub http_ua: String,
}

pub fn parse_tshark_json(text: &str) -> Result<(Vec<PacketIn>, Vec<TsharkExtra>), String> {
    let parsed: Value = serde_json::from_str(text).map_err(|e| format!("TShark JSON could not be read: {e}"))?;
    let Some(list) = parsed.as_array() else {
        return Err("TShark JSON was not a list of packets.".into());
    };
    let mut packets = Vec::new();
    let mut extras = Vec::new();
    for entry in list {
        let Some(layers) = layers_of(entry) else { continue };
        let pick = |key: &str| layers.get(key).map(text_of).unwrap_or_default();
        let n: i64 = pick("frame.number").parse().unwrap_or(0);
        if n <= 0 { continue; }
        let src = if pick("ip.src").is_empty() { pick("ipv6.src") } else { pick("ip.src") };
        let dst = if pick("ip.dst").is_empty() { pick("ipv6.dst") } else { pick("ip.dst") };
        let sp = pick("tcp.srcport").parse::<i64>().or_else(|_| pick("udp.srcport").parse()).unwrap_or(0);
        let dp = pick("tcp.dstport").parse::<i64>().or_else(|_| pick("udp.dstport").parse()).unwrap_or(0);
        let app = serde_json::json!({
            "modbusFunc": pick("modbus.func_code"),
            "modbusAddr": pick("modbus.reference_num"),
            "s7Func": pick("s7comm.param.func"),
            "dnp3Func": pick("dnp3.al.func"),
            "cipSvc": pick("cip.service"),
            "ja3": pick("tls.handshake.ja3"),
            "httpUa": pick("http.user_agent"),
            "smbDialect": pick("smb2.dialect"),
            "rdpKeyboard": pick("rdp.client.keyboard_layout"),
        });
        packets.push(PacketIn {
            n,
            ts: pick("frame.time_epoch").parse().unwrap_or(0.0),
            len: pick("frame.len").parse().unwrap_or(0),
            mac_src: pick("eth.src"),
            mac_dst: pick("eth.dst"),
            src,
            dst,
            sp,
            dp,
            ip_proto: pick("ip.proto").parse().unwrap_or(0),
            proto: pick("_ws.col.Protocol"),
            info: pick("_ws.col.Info"),
            layers: 0,
            app_json: app.to_string(),
        });
        extras.push(TsharkExtra {
            n,
            ja3: pick("tls.handshake.ja3"),
            rdp_keyboard: pick("rdp.client.keyboard_layout"),
            http_ua: pick("http.user_agent"),
        });
    }
    Ok((packets, extras))
}

pub fn ingest_json(case_id: &str, evidence_id: &str, json: &str) -> Result<usize, String> {
    let (packets, _) = parse_tshark_json(json)?;
    let count = packets.len();
    case::save_packets(case_id, evidence_id, "tshark", &packets)?;
    Ok(count)
}

pub fn run_tshark(bin: &Path, pcap: &Path, case_id: &str, evidence_id: &str) -> Result<String, String> {
    let mut cmd = Command::new(bin);
    cmd.arg("-r").arg(pcap).arg("-T").arg("json").arg("-n");
    for field in FIELDS {
        cmd.arg("-e").arg(field);
    }
    let output = cmd.output().map_err(|e| format!("Could not start TShark: {e}"))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("TShark failed ({}). The Primer view is unchanged. {err}", output.status));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let count = ingest_json(case_id, evidence_id, &text)?;
    Ok(format!("TShark stored {count} field rows."))
}

pub fn frame_verbose(bin: &Path, pcap: &Path, n: u64) -> Result<String, String> {
    if n == 0 || n > 50_000_000 {
        return Err("That frame number is not usable.".into());
    }
    let output = Command::new(bin)
        .arg("-r").arg(pcap)
        .arg("-Y").arg(format!("frame.number=={n}"))
        .arg("-V")
        .arg("-n")
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).chars().take(80_000).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mocked_tshark_json_keeps_the_frame_number() {
        let json = r#"[{"_source":{"layers":{"frame.number":["7"],"frame.time_epoch":["100.5"],"ip.src":["10.0.0.1"],"ip.dst":["10.0.0.2"],"tcp.dstport":["502"],"_ws.col.Protocol":["Modbus"],"_ws.col.Info":["Write"],"tls.handshake.ja3":["abc"]}}}]"#;
        let (packets, extras) = parse_tshark_json(json).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].n, 7);
        assert_eq!(packets[0].src, "10.0.0.1");
        assert_eq!(packets[0].dp, 502);
        assert_eq!(extras[0].ja3, "abc");
    }
}
