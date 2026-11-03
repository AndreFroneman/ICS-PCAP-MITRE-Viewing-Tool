use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::read::GzDecoder;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SCHEMA: &str = include_str!("schema.sql");

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Imported {
    pub case_id: String,
    pub evidence_id: String,
    pub sha256: String,
    pub source_sha256: String,
    pub stored_path: String,
    pub case_dir: String,
    pub size_bytes: u64,
    pub format: String,
    pub original_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexIn {
    pub n: i64,
    pub ts: f64,
    pub file_offset: i64,
    pub cap_len: i64,
    pub orig_len: i64,
    pub link_type: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketIn {
    pub n: i64,
    pub ts: f64,
    pub len: i64,
    #[serde(default)]
    pub mac_src: String,
    #[serde(default)]
    pub mac_dst: String,
    #[serde(default)]
    pub src: String,
    #[serde(default)]
    pub dst: String,
    #[serde(default)]
    pub sp: i64,
    #[serde(default)]
    pub dp: i64,
    #[serde(default)]
    pub ip_proto: i64,
    #[serde(default)]
    pub proto: String,
    #[serde(default)]
    pub info: String,
    #[serde(default)]
    pub layers: i64,
    #[serde(default)]
    pub app_json: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FindingIn {
    pub id: String,
    #[serde(default = "primer_engine")]
    pub engine: String,
    #[serde(default)]
    pub rule_id: String,
    pub title: String,
    pub summary: String,
    #[serde(default)]
    pub meaning: String,
    #[serde(default)]
    pub action: String,
    pub severity: String,
    #[serde(default = "low_conf")]
    pub confidence: String,
    #[serde(default = "one")]
    pub triage_level: i64,
    #[serde(default = "possible")]
    pub claim_status: String,
    #[serde(default)]
    pub alternative_explanation: String,
    #[serde(default = "pending")]
    pub validation: String,
    #[serde(default)]
    pub validated_by: String,
    #[serde(default)]
    pub validated_at: Option<String>,
    #[serde(default)]
    pub techniques: Vec<String>,
    #[serde(default = "possible")]
    pub technique_support: String,
    #[serde(default)]
    pub evidence: Vec<EvidenceIn>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceIn {
    pub n: i64,
    #[serde(default)]
    pub detail: String,
}

fn primer_engine() -> String { "primer".into() }
fn low_conf() -> String { "low".into() }
fn one() -> i64 { 1 }
fn possible() -> String { "possible".into() }
fn pending() -> String { "pending".into() }

pub fn cases_root() -> PathBuf {
    if let Ok(profile) = std::env::var("USERPROFILE") {
        return PathBuf::from(profile).join("Documents").join("Primer").join("Cases");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join("Documents").join("Primer").join("Cases");
    }
    std::env::temp_dir().join("Primer").join("Cases")
}

pub fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

fn hash_bytes(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

pub fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024 * 256];
    loop {
        let n = file.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(hex_encode(&hasher.finalize()))
}

fn copy_file(from: &Path, to: &Path) -> Result<u64, String> {
    let mut input = File::open(from).map_err(|e| e.to_string())?;
    let mut output = File::create(to).map_err(|e| e.to_string())?;
    let mut buf = [0u8; 1024 * 256];
    let mut total = 0u64;
    loop {
        let n = input.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 { break; }
        output.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        total += n as u64;
    }
    Ok(total)
}

fn sniff_format(path: &Path) -> String {
    let mut magic = [0u8; 4];
    let Ok(mut file) = File::open(path) else { return "unknown".into() };
    if file.read(&mut magic).ok() != Some(4) { return "unknown".into() }
    match magic {
        [0x0a, 0x0d, 0x0d, 0x0a] => "pcapng".into(),
        [0xd4, 0xc3, 0xb2, 0xa1] | [0xa1, 0xb2, 0xc3, 0xd4] | [0x4d, 0x3c, 0xb2, 0xa1] | [0xa1, 0xb2, 0x3c, 0x4d] => "pcap".into(),
        _ => "pcap".into(),
    }
}

fn is_gzip(path: &Path) -> bool {
    let mut magic = [0u8; 2];
    let Ok(mut file) = File::open(path) else { return false };
    file.read(&mut magic).ok() == Some(2) && magic == [0x1f, 0x8b]
}

pub fn case_dir(case_id: &str) -> PathBuf {
    cases_root().join(case_id)
}

pub fn open_db(case_id: &str) -> Result<Connection, String> {
    let path = case_dir(case_id).join("case.sqlite");
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    prepare(&conn)?;
    Ok(conn)
}

fn prepare(conn: &Connection) -> Result<(), String> {
    conn.busy_timeout(std::time::Duration::from_secs(8)).map_err(|e| e.to_string())?;
    conn.execute_batch("PRAGMA foreign_keys=ON;").map_err(|e| e.to_string())?;
    Ok(())
}

fn init_db(path: &Path) -> Result<Connection, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    prepare(&conn)?;
    conn.execute_batch(SCHEMA).map_err(|e| e.to_string())?;
    Ok(conn)
}

/// Copy the capture into the case, hash it, and mark that copy read-only.
/// Gzip is inflated first so later packet offsets refer to this file.
pub fn import_evidence(source: &Path, case_name: &str, investigator: &str) -> Result<Imported, String> {
    if !source.is_file() {
        return Err(format!("No capture at {}", source.display()));
    }
    let source_hash = sha256_file(source)?;
    let stamp = unix_secs();
    let case_id = format!("c-{}-{stamp}", &source_hash[..8]);
    let dir = case_dir(&case_id);
    let original_dir = dir.join("original");
    fs::create_dir_all(original_dir.join("..").join("suricata")).ok();
    fs::create_dir_all(&original_dir).map_err(|e| e.to_string())?;
    fs::create_dir_all(dir.join("suricata")).ok();
    fs::create_dir_all(dir.join("exports")).ok();
    fs::create_dir_all(dir.join("tshark")).ok();

    let original_name = source.file_name().and_then(|n| n.to_str()).unwrap_or("capture.pcap").to_string();
    let source_copy = original_dir.join(format!("source-{original_name}"));
    copy_file(source, &source_copy)?;

    let (evidence_path, format) = if is_gzip(&source_copy) {
        let mut decoder = GzDecoder::new(File::open(&source_copy).map_err(|e| e.to_string())?);
        let mut inflated = Vec::new();
        decoder.read_to_end(&mut inflated).map_err(|e| format!("Could not unpack gzip: {e}"))?;
        if inflated.len() > 512 * 1024 * 1024 {
            return Err("The gzip capture expands past 512 MB. Primer stopped rather than using all of the memory.".into());
        }
        let evidence_hash = hash_bytes(&inflated);
        let ext = if inflated.len() >= 4 && inflated[0] == 0x0a && inflated[1] == 0x0d { "pcapng" } else { "pcap" };
        let path = original_dir.join(format!("{evidence_hash}.{ext}"));
        File::create(&path).and_then(|mut f| f.write_all(&inflated)).map_err(|e| e.to_string())?;
        (path, if ext == "pcapng" { "gzip-pcapng" } else { "gzip-pcap" }.to_string())
    } else {
        let hash = source_hash.clone();
        let kind = sniff_format(&source_copy);
        let path = original_dir.join(format!("{hash}.{kind}"));
        if path != source_copy {
            fs::rename(&source_copy, &path).map_err(|e| e.to_string())?;
        }
        (path, kind)
    };

    let sha = sha256_file(&evidence_path)?;
    let size = fs::metadata(&evidence_path).map_err(|e| e.to_string())?.len();
    let mut perms = fs::metadata(&evidence_path).map_err(|e| e.to_string())?.permissions();
    perms.set_readonly(true);
    fs::set_permissions(&evidence_path, perms).map_err(|e| e.to_string())?;

    let evidence_id = format!("e-{sha}");
    let db_path = dir.join("case.sqlite");
    let conn = init_db(&db_path)?;
    let now = now_iso();
    let name = if case_name.trim().is_empty() { original_name.clone() } else { case_name.to_string() };
    conn.execute(
        "INSERT INTO case_meta (id, name, created_at, status, summary) VALUES (?1, ?2, ?3, 'open', '')",
        params![case_id, name, now],
    ).map_err(|e| e.to_string())?;
    let inv = if investigator.trim().is_empty() { "Investigator".to_string() } else { investigator.to_string() };
    conn.execute(
        "INSERT INTO investigators (id, name) VALUES ('inv-1', ?1)",
        params![inv],
    ).map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO evidence_files (id, original_name, source_path, stored_path, sha256, size_bytes, format, imported_at, warnings) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, '[]')",
        params![evidence_id, original_name, source.display().to_string(), evidence_path.display().to_string(), sha, size as i64, format, now],
    ).map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO custody_events (evidence_id, at, actor, action, sha256, detail) VALUES (?1, ?2, ?3, 'imported', ?4, ?5)",
        params![evidence_id, now, inv, sha, format!("source sha256 {source_hash}")],
    ).map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO activity_log (at, actor, action, detail) VALUES (?1, ?2, 'imported', ?3)",
        params![now, inv, format!("{original_name} {sha}")],
    ).map_err(|e| e.to_string())?;

    Ok(Imported {
        case_id,
        evidence_id,
        sha256: sha,
        source_sha256: source_hash,
        stored_path: evidence_path.display().to_string(),
        case_dir: dir.display().to_string(),
        size_bytes: size,
        format,
        original_name,
    })
}

pub fn verify_evidence(case_id: &str) -> Result<bool, String> {
    let conn = open_db(case_id)?;
    let (path, expected, evidence_id): (String, String, String) = conn.query_row(
        "SELECT stored_path, sha256, id FROM evidence_files LIMIT 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).map_err(|e| e.to_string())?;
    let actual = sha256_file(Path::new(&path))?;
    let ok = actual == expected;
    let detail = if ok { "hash matched the stored evidence".to_string() } else { format!("HASH MISMATCH stored {expected} now {actual}") };
    conn.execute(
        "INSERT INTO custody_events (evidence_id, at, actor, action, sha256, detail) VALUES (?1, ?2, '', 'verified', ?3, ?4)",
        params![evidence_id, now_iso(), actual, detail],
    ).map_err(|e| e.to_string())?;
    Ok(ok)
}

pub fn save_index(case_id: &str, evidence_id: &str, rows: &[IndexIn]) -> Result<(), String> {
    let conn = open_db(case_id)?;
    let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
    for row in rows {
        tx.execute(
            "INSERT OR REPLACE INTO packet_index (evidence_id, n, ts, file_offset, cap_len, orig_len, link_type) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![evidence_id, row.n, row.ts, row.file_offset, row.cap_len, row.orig_len, row.link_type],
        ).map_err(|e| e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())
}

pub fn packet_numbers(case_id: &str) -> Result<Vec<i64>, String> {
    let conn = open_db(case_id)?;
    let mut stmt = conn.prepare("SELECT n FROM packet_index ORDER BY n").map_err(|e| e.to_string())?;
    let rows = stmt.query_map([], |row| row.get(0)).map_err(|e| e.to_string())?;
    rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
}

pub fn save_packets(case_id: &str, evidence_id: &str, engine: &str, rows: &[PacketIn]) -> Result<(), String> {
    let conn = open_db(case_id)?;
    let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
    for row in rows {
        let app = if row.app_json.is_empty() { "{}".to_string() } else { row.app_json.clone() };
        tx.execute(
            "INSERT OR REPLACE INTO packets (evidence_id, n, engine, ts, len, mac_src, mac_dst, src, dst, src_port, dst_port, ip_proto, proto, info, layers, app_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![evidence_id, row.n, engine, row.ts, row.len, row.mac_src, row.mac_dst, row.src, row.dst, row.sp, row.dp, row.ip_proto, row.proto, row.info, row.layers, app],
        ).map_err(|e| e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())
}

pub fn save_findings(case_id: &str, evidence_id: &str, findings: &[FindingIn], replace_engines: &[&str]) -> Result<(), String> {
    let conn = open_db(case_id)?;
    let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
    for engine in replace_engines {
        let ids: Vec<String> = {
            let mut stmt = tx.prepare("SELECT id FROM findings WHERE evidence_id = ?1 AND engine = ?2").map_err(|e| e.to_string())?;
            let rows = stmt.query_map(params![evidence_id, engine], |row| row.get(0)).map_err(|e| e.to_string())?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?
        };
        for id in ids {
            tx.execute("DELETE FROM finding_packets WHERE finding_id = ?1", params![id]).map_err(|e| e.to_string())?;
            tx.execute("DELETE FROM findings WHERE id = ?1", params![id]).map_err(|e| e.to_string())?;
        }
    }
    for finding in findings {
        let techniques = serde_json::to_string(&finding.techniques).unwrap_or_else(|_| "[]".into());
        tx.execute(
            "INSERT OR REPLACE INTO findings (id, evidence_id, engine, rule_id, title, summary, meaning, action, severity, confidence, triage_level, claim_status, alternative_explanation, validation, validated_by, validated_at, techniques, technique_support) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            params![finding.id, evidence_id, finding.engine, finding.rule_id, finding.title, finding.summary, finding.meaning, finding.action, finding.severity, finding.confidence, finding.triage_level, finding.claim_status, finding.alternative_explanation, finding.validation, finding.validated_by, finding.validated_at, techniques, finding.technique_support],
        ).map_err(|e| e.to_string())?;
        for ev in &finding.evidence {
            tx.execute(
                "INSERT OR REPLACE INTO finding_packets (finding_id, evidence_id, packet_n, detail) VALUES (?1, ?2, ?3, ?4)",
                params![finding.id, evidence_id, ev.n, ev.detail],
            ).map_err(|e| e.to_string())?;
        }
    }
    tx.commit().map_err(|e| e.to_string())
}

pub fn list_findings(case_id: &str) -> Result<Vec<FindingIn>, String> {
    let conn = open_db(case_id)?;
    let mut stmt = conn.prepare("SELECT id, engine, rule_id, title, summary, meaning, action, severity, confidence, triage_level, claim_status, alternative_explanation, validation, validated_by, validated_at, techniques, technique_support FROM findings").map_err(|e| e.to_string())?;
    let rows = stmt.query_map([], |row| {
        let techniques: String = row.get(15)?;
        Ok(FindingIn {
            id: row.get(0)?,
            engine: row.get(1)?,
            rule_id: row.get(2)?,
            title: row.get(3)?,
            summary: row.get(4)?,
            meaning: row.get(5)?,
            action: row.get(6)?,
            severity: row.get(7)?,
            confidence: row.get(8)?,
            triage_level: row.get(9)?,
            claim_status: row.get(10)?,
            alternative_explanation: row.get(11)?,
            validation: row.get(12)?,
            validated_by: row.get(13)?,
            validated_at: row.get(14)?,
            techniques: serde_json::from_str(&techniques).unwrap_or_default(),
            technique_support: row.get(16)?,
            evidence: Vec::new(),
        })
    }).map_err(|e| e.to_string())?;
    let mut findings = rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?;
    for finding in &mut findings {
        let mut ev = conn.prepare("SELECT packet_n, detail FROM finding_packets WHERE finding_id = ?1 ORDER BY packet_n").map_err(|e| e.to_string())?;
        let packets = ev.query_map(params![finding.id], |row| Ok(EvidenceIn { n: row.get(0)?, detail: row.get(1)? })).map_err(|e| e.to_string())?;
        finding.evidence = packets.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?;
    }
    Ok(findings)
}

pub fn set_validation(case_id: &str, finding_id: &str, validation: &str, actor: &str, note: &str) -> Result<(), String> {
    let allowed = ["pending", "approved", "rejected", "escalated"];
    if !allowed.contains(&validation) {
        return Err("Validation must be pending, approved, rejected, or escalated.".into());
    }
    let conn = open_db(case_id)?;
    let now = now_iso();
    let changed = conn.execute(
        "UPDATE findings SET validation = ?1, validated_by = ?2, validated_at = ?3 WHERE id = ?4",
        params![validation, actor, now, finding_id],
    ).map_err(|e| e.to_string())?;
    if changed == 0 { return Err("That finding is not in this case.".into()); }
    conn.execute(
        "INSERT INTO activity_log (at, actor, action, detail) VALUES (?1, ?2, ?3, ?4)",
        params![now, actor, validation, format!("{finding_id} {note}")],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn add_note(case_id: &str, finding_id: &str, body: &str, author: &str) -> Result<(), String> {
    let conn = open_db(case_id)?;
    let now = now_iso();
    let id = format!("note-{}", unix_secs());
    let finding = if finding_id.is_empty() { None } else { Some(finding_id) };
    conn.execute(
        "INSERT INTO notes (id, finding_id, body, author, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![id, finding, body, author, now],
    ).map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO activity_log (at, actor, action, detail) VALUES (?1, ?2, 'note', ?3)",
        params![now, author, body],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn activity(case_id: &str) -> Result<Vec<serde_json::Value>, String> {
    let conn = open_db(case_id)?;
    let mut stmt = conn.prepare("SELECT at, actor, action, detail FROM activity_log ORDER BY id").map_err(|e| e.to_string())?;
    let rows = stmt.query_map([], |row| {
        Ok(serde_json::json!({
            "at": row.get::<_, String>(0)?,
            "actor": row.get::<_, String>(1)?,
            "action": row.get::<_, String>(2)?,
            "detail": row.get::<_, String>(3)?,
        }))
    }).map_err(|e| e.to_string())?;
    rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
}

pub fn list_cases() -> Result<Vec<serde_json::Value>, String> {
    let root = cases_root();
    if !root.exists() { return Ok(Vec::new()); }
    let mut out = Vec::new();
    for entry in fs::read_dir(&root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let db = entry.path().join("case.sqlite");
        if !db.is_file() { continue; }
        let Ok(conn) = Connection::open(&db) else { continue };
        let Ok(row) = conn.query_row(
            "SELECT id, name, created_at, status FROM case_meta LIMIT 1",
            [],
            |row| Ok(serde_json::json!({ "id": row.get::<_, String>(0)?, "name": row.get::<_, String>(1)?, "createdAt": row.get::<_, String>(2)?, "status": row.get::<_, String>(3)? })),
        ) else { continue };
        out.push(row);
    }
    Ok(out)
}

pub fn save_assets(case_id: &str, evidence_id: &str, assets: &[serde_json::Value]) -> Result<(), String> {
    let conn = open_db(case_id)?;
    let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
    tx.execute("DELETE FROM asset_evidence WHERE evidence_id = ?1", params![evidence_id]).map_err(|e| e.to_string())?;
    tx.execute("DELETE FROM assets WHERE evidence_id = ?1", params![evidence_id]).map_err(|e| e.to_string())?;
    for asset in assets {
        let id = asset.get("id").and_then(|v| v.as_str()).unwrap_or("asset");
        tx.execute(
            "INSERT OR REPLACE INTO assets (id, evidence_id, ip, mac, hostname, role, confidence, hypothesis, alternate_hypothesis, first_seen, last_seen) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                id,
                evidence_id,
                asset.get("ip").and_then(|v| v.as_str()).unwrap_or(""),
                asset.get("mac").and_then(|v| v.as_str()).unwrap_or(""),
                asset.get("hostname").and_then(|v| v.as_str()).unwrap_or(""),
                asset.get("role").and_then(|v| v.as_str()).unwrap_or("unknown"),
                asset.get("confidence").and_then(|v| v.as_str()).unwrap_or("low"),
                asset.get("hypothesis").and_then(|v| v.as_str()).unwrap_or(""),
                asset.get("alternateHypothesis").and_then(|v| v.as_str()).unwrap_or(""),
                asset.get("firstSeen").and_then(|v| v.as_f64()),
                asset.get("lastSeen").and_then(|v| v.as_f64()),
            ],
        ).map_err(|e| e.to_string())?;
        if let Some(evidence) = asset.get("evidence").and_then(|v| v.as_array()) {
            for item in evidence {
                let n = item.get("n").and_then(|v| v.as_i64()).unwrap_or(0);
                let detail = item.get("detail").and_then(|v| v.as_str()).unwrap_or("");
                tx.execute(
                    "INSERT INTO asset_evidence (asset_id, evidence_id, packet_n, detail) VALUES (?1, ?2, ?3, ?4)",
                    params![id, evidence_id, n, detail],
                ).map_err(|e| e.to_string())?;
            }
        }
    }
    tx.commit().map_err(|e| e.to_string())
}

pub fn save_fingerprints(case_id: &str, evidence_id: &str, rows: &[serde_json::Value]) -> Result<(), String> {
    let conn = open_db(case_id)?;
    let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
    tx.execute("DELETE FROM fingerprints WHERE evidence_id = ?1", params![evidence_id]).map_err(|e| e.to_string())?;
    for row in rows {
        tx.execute(
            "INSERT INTO fingerprints (id, evidence_id, kind, value, packet_n, observed_fact, hypothesis, attribution_note) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                row.get("id").and_then(|v| v.as_str()).unwrap_or("fp"),
                evidence_id,
                row.get("kind").and_then(|v| v.as_str()).unwrap_or(""),
                row.get("value").and_then(|v| v.as_str()).unwrap_or(""),
                row.get("packetN").and_then(|v| v.as_i64()).unwrap_or(0),
                row.get("observedFact").and_then(|v| v.as_str()).unwrap_or(""),
                row.get("hypothesis").and_then(|v| v.as_str()).unwrap_or(""),
                row.get("attributionNote").and_then(|v| v.as_str()).unwrap_or("Observed technical fact. Not evidence of nationality or sponsorship."),
            ],
        ).map_err(|e| e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())
}

pub fn read_span(path: &Path, offset: u64, len: u64) -> Result<Vec<u8>, String> {
    if len > 2_000_000 {
        return Err("Refusing to pull more than 2 MB for a single packet.".into());
    }
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; len as usize];
    file.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_pcap() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        v.extend_from_slice(&2u16.to_le_bytes());
        v.extend_from_slice(&4u16.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&65535u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&4u32.to_le_bytes());
        v.extend_from_slice(&4u32.to_le_bytes());
        v.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        v
    }

    #[test]
    fn import_hashes_and_reopens_the_same_packet_numbers() {
        let dir = std::env::temp_dir().join(format!("primer-case-{}", unix_secs()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let src = dir.join("sample.pcap");
        fs::write(&src, tiny_pcap()).unwrap();
        std::env::set_var("HOME", &dir);
        // cases_root uses HOME/Documents/Primer/Cases. Point HOME at dir so we don't touch a real profile.
        // The function joins Documents/Primer/Cases under HOME. Create nothing else.
        let imported = import_evidence(&src, "Sample", "A. Tester").unwrap();
        let expected = hash_bytes(&tiny_pcap());
        assert_eq!(imported.sha256, expected);
        assert!(Path::new(&imported.stored_path).metadata().unwrap().permissions().readonly());
        save_index(&imported.case_id, &imported.evidence_id, &[IndexIn {
            n: 1, ts: 1_700_000_000.0, file_offset: 40, cap_len: 4, orig_len: 4, link_type: 1,
        }]).unwrap();
        let numbers = packet_numbers(&imported.case_id).unwrap();
        assert_eq!(numbers, vec![1]);
        let again = sha256_file(Path::new(&imported.stored_path)).unwrap();
        assert_eq!(again, expected);
        assert!(verify_evidence(&imported.case_id).unwrap());
        let bytes = read_span(Path::new(&imported.stored_path), 40, 4).unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
        let _ = fs::remove_dir_all(dir.join("Documents"));
    }
}
