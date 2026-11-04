use rusqlite::params;

use crate::case::{self, EvidenceIn, FindingIn};

fn shares(a: &str, b: &str) -> bool {
    let left = a.to_ascii_lowercase();
    let right = b.to_ascii_lowercase();
    for key in ["modbus", "s7", "dnp3", "iec", "bacnet", "scan", "smb", "dns", "mqtt", "write", "password"] {
        if left.contains(key) && right.contains(key) {
            return true;
        }
    }
    false
}

/// Collapse a Suricata hit into the Primer card when they cite the same packets and the same behaviour.
pub fn correlate_case(case_id: &str) -> Result<usize, String> {
    let findings = case::list_findings(case_id)?;
    let primer: Vec<&FindingIn> = findings.iter().filter(|f| f.engine == "primer" || f.engine == "correlation").collect();
    let suricata: Vec<&FindingIn> = findings.iter().filter(|f| f.engine == "suricata").collect();
    let mut merged = 0usize;
    let mut consumed: Vec<String> = Vec::new();
    let mut updates: Vec<FindingIn> = Vec::new();
    for left in primer {
        let partner = suricata.iter().find(|right| {
            if consumed.iter().any(|id| id == &right.id) { return false; }
            let overlap = right.evidence.iter().any(|e| left.evidence.iter().any(|p| p.n == e.n));
            if !overlap { return false; }
            let subset = right.evidence.iter().all(|e| left.evidence.iter().any(|p| p.n == e.n));
            shares(&left.title, &right.title) || shares(&left.summary, &right.title) || subset
        });
        let Some(right) = partner else { continue };
        consumed.push(right.id.clone());
        let mut evidence = left.evidence.clone();
        for item in &right.evidence {
            if !evidence.iter().any(|e| e.n == item.n) {
                evidence.push(EvidenceIn { n: item.n, detail: item.detail.clone() });
            }
        }
        let mut next = left.clone();
        next.engine = "correlation".into();
        next.rule_id = right.rule_id.clone();
        next.summary = format!("{} Also raised by Suricata ({}): {}.", left.summary, right.rule_id, right.title);
        next.evidence = evidence;
        updates.push(next);
        merged += 1;
    }
    if updates.is_empty() { return Ok(0); }
    let evidence_id = {
        let conn = case::open_db(case_id)?;
        conn.query_row("SELECT id FROM evidence_files LIMIT 1", [], |row| row.get::<_, String>(0)).map_err(|e| e.to_string())?
    };
    case::save_findings(case_id, &evidence_id, &updates, &[])?;
    let conn = case::open_db(case_id)?;
    for id in &consumed {
        conn.execute("DELETE FROM finding_packets WHERE finding_id = ?1", params![id]).map_err(|e| e.to_string())?;
        conn.execute("DELETE FROM findings WHERE id = ?1", params![id]).map_err(|e| e.to_string())?;
    }
    // The updated primer row was inserted with the same id and engine correlation via INSERT OR REPLACE.
    let _ = evidence_id;
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case::{import_evidence, FindingIn, EvidenceIn};
    use std::fs;

    #[test]
    fn overlapping_modbus_hit_becomes_one_card() {
        let dir = std::env::temp_dir().join(format!("primer-corr-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let src = dir.join("one.pcap");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&4u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&65535u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        fs::write(&src, &bytes).unwrap();
        let old_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", &dir);
        let imported = import_evidence(&src, "corr", "tester").unwrap();
        let primer = FindingIn {
            id: "modbus-write".into(),
            engine: "primer".into(),
            rule_id: String::new(),
            title: "Modbus write to a controller".into(),
            summary: "A Modbus write was decoded.".into(),
            meaning: String::new(),
            action: String::new(),
            severity: "high".into(),
            confidence: "high".into(),
            triage_level: 2,
            claim_status: "observed".into(),
            alternative_explanation: "maintenance".into(),
            validation: "pending".into(),
            validated_by: String::new(),
            validated_at: None,
            techniques: vec!["T0836".into()],
            technique_support: "possible".into(),
            evidence: vec![EvidenceIn { n: 12, detail: "function 16".into() }],
        };
        let suricata = FindingIn {
            id: "suricata:1:12".into(),
            engine: "suricata".into(),
            rule_id: "sid:1".into(),
            title: "ET POLICY Modbus write".into(),
            summary: "rule".into(),
            meaning: String::new(),
            action: String::new(),
            severity: "high".into(),
            confidence: "medium".into(),
            triage_level: 2,
            claim_status: "possible".into(),
            alternative_explanation: String::new(),
            validation: "pending".into(),
            validated_by: String::new(),
            validated_at: None,
            techniques: vec![],
            technique_support: "possible".into(),
            evidence: vec![EvidenceIn { n: 12, detail: "rule".into() }],
        };
        case::save_findings(&imported.case_id, &imported.evidence_id, &[primer, suricata], &[]).unwrap();
        let n = correlate_case(&imported.case_id).unwrap();
        assert_eq!(n, 1);
        let left = case::list_findings(&imported.case_id).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].engine, "correlation");
        assert_eq!(left[0].rule_id, "sid:1");
        if let Some(home) = old_home { std::env::set_var("HOME", home); }
    }
}
