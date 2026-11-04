use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::case::{self, EvidenceIn, FindingIn};
use crate::tshark::which;

/// Why the installer does not contain suricata.exe.
/// A Windows build that is linked to Npcap's wpcap.dll refuses to start, even for `suricata -r`,
/// when that DLL is missing. Npcap's free licence also forbids bundling the driver.
/// An MSYS2 libpcap build can read a file without Npcap, but that binary was not proven here
/// on a clean Windows 10 machine, so it is not shipped. The hook below runs `-r` if you place one.
pub const NOT_BUNDLED: &str = "Suricata is not in this installer. The usual Windows build looks for Npcap's wpcap.dll and will not start without it, even when reading a file. Npcap cannot be bundled with Primer. Put a Suricata build that runs `suricata -r` with no Npcap next to Primer, or leave detection to Primer's own checks. A missing Suricata does not hide industrial findings.";

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuricataStatus {
    pub bundled: bool,
    pub path: String,
    pub note: String,
}

pub fn locate_suricata(extra: &[PathBuf]) -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PRIMER_SURICATA") {
        let candidate = PathBuf::from(path);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    for dir in extra {
        for name in ["suricata.exe", "suricata"] {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    which(if cfg!(windows) { "suricata.exe" } else { "suricata" })
}

pub fn status(extra: &[PathBuf]) -> SuricataStatus {
    match locate_suricata(extra) {
        Some(path) => SuricataStatus {
            bundled: false,
            path: path.display().to_string(),
            note: "A Suricata program was found on this computer. Primer will try `suricata -r` and will not install Npcap. If it fails because wpcap.dll is missing, install is not the fix Primer will apply.".into(),
        },
        None => SuricataStatus { bundled: false, path: String::new(), note: NOT_BUNDLED.into() },
    }
}

pub fn parse_eve(text: &str, rule_date: &str) -> Vec<FindingIn> {
    let mut findings = Vec::new();
    let trimmed = text.trim();
    if trimmed.is_empty() { return findings; }
    let lines: Vec<String> = if trimmed.starts_with('[') {
        serde_json::from_str::<Vec<serde_json::Value>>(trimmed).unwrap_or_default().into_iter().map(|v| v.to_string()).collect()
    } else {
        trimmed.lines().map(|l| l.to_string()).collect()
    };
    for line in lines {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
        if value.get("event_type").and_then(|v| v.as_str()) != Some("alert") { continue; }
        let alert = value.get("alert").cloned().unwrap_or(serde_json::Value::Null);
        let sid = alert.get("signature_id").and_then(|v| v.as_i64()).unwrap_or(0);
        let signature = alert.get("signature").and_then(|v| v.as_str()).unwrap_or("Suricata alert").to_string();
        let severity_n = alert.get("severity").and_then(|v| v.as_i64()).unwrap_or(3);
        let severity = if severity_n <= 1 { "high" } else if severity_n == 2 { "medium" } else { "low" };
        let packet = value.get("pcap_cnt").and_then(|v| v.as_i64()).unwrap_or(0);
        let date_note = if rule_date.is_empty() { String::new() } else { format!(" Rule snapshot: {rule_date}.") };
        findings.push(FindingIn {
            id: format!("suricata:{sid}:{packet}"),
            engine: "suricata".into(),
            rule_id: if sid > 0 { format!("sid:{sid}") } else { String::new() },
            title: signature.clone(),
            summary: format!("{signature}.{date_note} A signature hit is a lead. It is not proof of an exploit, and it is not a substitute for the industrial checks."),
            meaning: "Suricata compared the bytes to a rule.".into(),
            action: "Open the packet and decide. Reject the hit if it is noise.".into(),
            severity: severity.into(),
            confidence: "medium".into(),
            triage_level: 2,
            claim_status: "possible".into(),
            alternative_explanation: "A rule can fire on a lab file or a lookalike.".into(),
            validation: "pending".into(),
            validated_by: String::new(),
            validated_at: None,
            techniques: Vec::new(),
            technique_support: "possible".into(),
            evidence: if packet > 0 { vec![EvidenceIn { n: packet, detail: signature }] } else { Vec::new() },
        });
    }
    findings
}

pub fn run_suricata(bin: &Path, pcap: &Path, case_id: &str, evidence_id: &str, config: &Path) -> Result<String, String> {
    let log_dir = case::case_dir(case_id).join("suricata");
    fs::create_dir_all(&log_dir).map_err(|e| e.to_string())?;
    let output = Command::new(bin)
        .arg("-r").arg(pcap)
        .arg("-l").arg(&log_dir)
        .arg("-c").arg(config)
        .output()
        .map_err(|e| format!("Could not start Suricata: {e}"))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Suricata did not accept this file ({}) . Primer's own findings are unchanged. {err}", output.status));
    }
    let eve_path = log_dir.join("eve.json");
    let text = fs::read_to_string(&eve_path).unwrap_or_default();
    let findings = parse_eve(&text, "bundled-or-local");
    let count = findings.len();
    case::save_findings(case_id, evidence_id, &findings, &["suricata"])?;
    Ok(format!("Suricata wrote {count} alerts."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eve_alert_keeps_the_packet_number_and_the_rule() {
        let text = r#"{"timestamp":"2026-11-02T00:00:00.000000+0000","event_type":"alert","src_ip":"10.1.1.8","dest_ip":"10.1.1.50","proto":"TCP","pcap_cnt":12,"alert":{"signature_id":2024897,"signature":"ET POLICY Modbus write","severity":1,"category":"Misc"}}"#;
        let findings = parse_eve(text, "2026-10-01");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence[0].n, 12);
        assert_eq!(findings[0].rule_id, "sid:2024897");
        assert!(findings[0].summary.contains("2026-10-01"));
        assert!(!status(&[]).bundled);
        assert!(status(&[]).note.contains("Npcap") || status(&[]).note.contains("wpcap") || status(&[]).note.contains("Suricata"));
    }
}
