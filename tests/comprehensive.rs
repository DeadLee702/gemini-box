use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use zip::ZipArchive;

// ─── TriageAnalysis: all 13 status codes ─────────────────────────────

// We need to call into the analyze module. Since it's a bin target, we
// duplicate the essential types here for testing, then test the gen_fixtures
// and evk binaries via subprocess.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageAnalysis {
    pub file_path: String,
    pub status_code: String,
    pub incident_type: String,
    pub confidence: f32,
    pub analysis: String,
    pub recommended_action: String,
    pub severity: String,
    pub chain_of_custody_valid: bool,
    pub raw_code: u16,
}

impl TriageAnalysis {
    pub fn new(
        file_path: impl Into<String>,
        status_code: u16,
        incident_type: impl Into<String>,
    ) -> Self {
        let (confidence, analysis, recommended_action, severity) =
            Self::classify_incident(status_code);

        TriageAnalysis {
            file_path: file_path.into(),
            status_code: format!("0x{:04X}", status_code),
            incident_type: incident_type.into(),
            confidence,
            analysis,
            recommended_action,
            severity,
            chain_of_custody_valid: true,
            raw_code: status_code,
        }
    }

    fn classify_incident(status_code: u16) -> (f32, String, String, String) {
        match status_code {
            0x0000 => (1.0, "Bundle verified as clean. No malicious artifacts detected.".into(), "allow".into(), "LOW".into()),
            0x0F2E => (0.95, "Handoff conflict detected: Step executed by wrong actor. Indicates role-based access control violation or process orchestration failure.".into(), "block".into(), "HIGH".into()),
            0x0E1A => (0.92, "Race condition detected: Concurrent modification without proper synchronization. May indicate state corruption or timing-based vulnerability.".into(), "quarantine".into(), "HIGH".into()),
            0x0D44 => (0.90, "Orphaned step detected: Process step with no parent/owner. Indicates incomplete workflow state or dangling process.".into(), "escalate".into(), "MEDIUM".into()),
            0x1A4F => (0.98, "Transaction replay attack detected: Prior transaction re-executed. Critical security incident indicating attacker replay capability.".into(), "block".into(), "CRITICAL".into()),
            0x1B88 => (0.88, "Schema mutation detected: Unexpected data structure change. May indicate tampering, version mismatch, or injection attack.".into(), "quarantine".into(), "MEDIUM".into()),
            0x1C2B => (0.96, "Log truncation detected: Critical audit trail entries removed. Indicates deliberate evidence destruction or forensic tampering.".into(), "escalate".into(), "CRITICAL".into()),
            0x2A90 => (0.94, "Packet modification detected: In-transit data tampering. Network layer compromise or man-in-the-middle attack suspected.".into(), "block".into(), "HIGH".into()),
            0x2B11 => (0.85, "Timestamp drift detected: Significant clock skew detected. May indicate system compromise, timezone misconfiguration, or temporal attack.".into(), "escalate".into(), "MEDIUM".into()),
            0x2C7F => (0.97, "API spoofing detected: Impersonated service endpoint. Attacker intercepted or redirected API calls to malicious endpoint.".into(), "block".into(), "CRITICAL".into()),
            0x3A01 => (0.91, "Prompt injection detected: Malicious input to LLM/system command interface. Attacker attempted to manipulate system behavior through user input.".into(), "quarantine".into(), "HIGH".into()),
            0x3B99 => (0.99, "Entropy leakage detected: Cryptographic material exposed. CRITICAL: Cryptographic keys or random seeds may have been compromised.".into(), "escalate".into(), "CRITICAL".into()),
            0x3C4D => (0.93, "Register forgery detected: Tampered hardware/software register state. Indicates low-level compromise or hardware-level attack.".into(), "block".into(), "CRITICAL".into()),
            _ => (0.70, format!("Unknown malicious status code detected: 0x{:04X}. Recommend manual review and forensic investigation.", status_code), "escalate".into(), "MEDIUM".into()),
        }
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

// ─── Unit tests for TriageAnalysis ────────────────────────────────────

struct CodeExpectation {
    code: u16,
    confidence: f32,
    action: &'static str,
    severity: &'static str,
    incident_type: &'static str,
}

fn all_known_codes() -> Vec<CodeExpectation> {
    vec![
        CodeExpectation {
            code: 0x0000,
            confidence: 1.0,
            action: "allow",
            severity: "LOW",
            incident_type: "Clean",
        },
        CodeExpectation {
            code: 0x0F2E,
            confidence: 0.95,
            action: "block",
            severity: "HIGH",
            incident_type: "Handoff Conflict",
        },
        CodeExpectation {
            code: 0x0E1A,
            confidence: 0.92,
            action: "quarantine",
            severity: "HIGH",
            incident_type: "Race Condition",
        },
        CodeExpectation {
            code: 0x0D44,
            confidence: 0.90,
            action: "escalate",
            severity: "MEDIUM",
            incident_type: "Orphaned Step",
        },
        CodeExpectation {
            code: 0x1A4F,
            confidence: 0.98,
            action: "block",
            severity: "CRITICAL",
            incident_type: "Transaction Replay",
        },
        CodeExpectation {
            code: 0x1B88,
            confidence: 0.88,
            action: "quarantine",
            severity: "MEDIUM",
            incident_type: "Schema Mutation",
        },
        CodeExpectation {
            code: 0x1C2B,
            confidence: 0.96,
            action: "escalate",
            severity: "CRITICAL",
            incident_type: "Log Truncation",
        },
        CodeExpectation {
            code: 0x2A90,
            confidence: 0.94,
            action: "block",
            severity: "HIGH",
            incident_type: "Packet Modification",
        },
        CodeExpectation {
            code: 0x2B11,
            confidence: 0.85,
            action: "escalate",
            severity: "MEDIUM",
            incident_type: "Timestamp Drift",
        },
        CodeExpectation {
            code: 0x2C7F,
            confidence: 0.97,
            action: "block",
            severity: "CRITICAL",
            incident_type: "API Spoofing",
        },
        CodeExpectation {
            code: 0x3A01,
            confidence: 0.91,
            action: "quarantine",
            severity: "HIGH",
            incident_type: "Prompt Injection",
        },
        CodeExpectation {
            code: 0x3B99,
            confidence: 0.99,
            action: "escalate",
            severity: "CRITICAL",
            incident_type: "Entropy Leakage",
        },
        CodeExpectation {
            code: 0x3C4D,
            confidence: 0.93,
            action: "block",
            severity: "CRITICAL",
            incident_type: "Register Forgery",
        },
    ]
}

#[test]
fn test_all_known_status_codes() {
    for exp in all_known_codes() {
        let analysis = TriageAnalysis::new("test.evkp", exp.code, exp.incident_type);
        assert_eq!(
            analysis.raw_code, exp.code,
            "raw_code mismatch for 0x{:04X}",
            exp.code
        );
        assert_eq!(
            analysis.status_code,
            format!("0x{:04X}", exp.code),
            "status_code format for 0x{:04X}",
            exp.code
        );
        assert_eq!(
            analysis.confidence, exp.confidence,
            "confidence for 0x{:04X}",
            exp.code
        );
        assert_eq!(
            analysis.recommended_action, exp.action,
            "action for 0x{:04X}",
            exp.code
        );
        assert_eq!(
            analysis.severity, exp.severity,
            "severity for 0x{:04X}",
            exp.code
        );
        assert_eq!(analysis.incident_type, exp.incident_type);
        assert!(
            analysis.chain_of_custody_valid,
            "chain_of_custody should be true by default"
        );
        assert!(
            !analysis.analysis.is_empty(),
            "analysis text should not be empty for 0x{:04X}",
            exp.code
        );
    }
}

#[test]
fn test_unknown_status_code_defaults() {
    let analysis = TriageAnalysis::new("unknown.evkp", 0xFFFF, "Unknown Incident");
    assert_eq!(analysis.confidence, 0.70);
    assert_eq!(analysis.recommended_action, "escalate");
    assert_eq!(analysis.severity, "MEDIUM");
    assert!(analysis.analysis.contains("0xFFFF"));
}

#[test]
fn test_unknown_code_in_analysis_text() {
    for code in [0x0001, 0x1234, 0xABCD, 0xFFFE] {
        let analysis = TriageAnalysis::new("test.evkp", code, "Unknown");
        assert!(analysis.analysis.contains(&format!("0x{:04X}", code)));
    }
}

#[test]
fn test_status_code_hex_formatting() {
    for (code, expected) in [
        (0x0000u16, "0x0000"),
        (0x0F2E, "0x0F2E"),
        (0x3C4D, "0x3C4D"),
        (0xFFFF, "0xFFFF"),
    ] {
        let analysis = TriageAnalysis::new("test.evkp", code, "Test");
        assert_eq!(analysis.status_code, expected);
    }
}

#[test]
fn test_json_serialization_all_codes() {
    for exp in all_known_codes() {
        let analysis = TriageAnalysis::new("test.evkp", exp.code, exp.incident_type);
        let json = analysis.to_json().expect("JSON serialization failed");
        assert!(
            json.contains(&format!("0x{:04X}", exp.code)),
            "JSON should contain hex code for 0x{:04X}",
            exp.code
        );
        assert!(
            json.contains(exp.incident_type),
            "JSON should contain incident type for 0x{:04X}",
            exp.code
        );
        assert!(
            json.contains(exp.action),
            "JSON should contain action for 0x{:04X}",
            exp.code
        );
        assert!(
            json.contains(exp.severity),
            "JSON should contain severity for 0x{:04X}",
            exp.code
        );
        assert!(json.contains("chain_of_custody_valid"));
        assert!(json.contains("raw_code"));
    }
}

#[test]
fn test_json_round_trip() {
    let analysis = TriageAnalysis::new("round_trip.evkp", 0x1A4F, "Transaction Replay");
    let json = analysis.to_json().unwrap();
    let deserialized: TriageAnalysis = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.raw_code, 0x1A4F);
    assert_eq!(deserialized.incident_type, "Transaction Replay");
    assert_eq!(deserialized.confidence, 0.98);
    assert_eq!(deserialized.recommended_action, "block");
    assert_eq!(deserialized.severity, "CRITICAL");
}

#[test]
fn test_json_array_serialization() {
    let results: Vec<TriageAnalysis> = all_known_codes()
        .iter()
        .map(|exp| TriageAnalysis::new("batch.evkp", exp.code, exp.incident_type))
        .collect();
    let json = serde_json::to_string_pretty(&results).unwrap();
    let deserialized: Vec<TriageAnalysis> = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.len(), 13);
    for (i, exp) in all_known_codes().iter().enumerate() {
        assert_eq!(deserialized[i].raw_code, exp.code);
    }
}

#[test]
fn test_confidence_range_valid() {
    for exp in all_known_codes() {
        assert!(
            exp.confidence > 0.0 && exp.confidence <= 1.0,
            "confidence {} out of range for 0x{:04X}",
            exp.confidence,
            exp.code
        );
    }
    let unknown = TriageAnalysis::new("test.evkp", 0xBEEF, "Unknown");
    assert!(unknown.confidence > 0.0 && unknown.confidence <= 1.0);
}

#[test]
fn test_severity_levels_are_valid() {
    let valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
    for exp in all_known_codes() {
        assert!(
            valid_severities.contains(&exp.severity),
            "invalid severity {} for 0x{:04X}",
            exp.severity,
            exp.code
        );
    }
}

#[test]
fn test_actions_are_valid() {
    let valid_actions = ["allow", "block", "quarantine", "escalate"];
    for exp in all_known_codes() {
        assert!(
            valid_actions.contains(&exp.action),
            "invalid action {} for 0x{:04X}",
            exp.action,
            exp.code
        );
    }
    let unknown = TriageAnalysis::new("test.evkp", 0xDEAD, "Unknown");
    assert!(valid_actions.contains(&unknown.recommended_action.as_str()));
}

#[test]
fn test_file_path_preserved() {
    for path in [
        "incident_7f3a.evkp",
        "/abs/path/to/file.evkp",
        "relative/path.evkp",
    ] {
        let analysis = TriageAnalysis::new(path, 0x0000, "Clean");
        assert_eq!(analysis.file_path, path);
    }
}

// ─── analyze_incident function tests ─────────────────────────────────

fn analyze_incident(file_path: &str) -> Result<TriageAnalysis, String> {
    let file_data = fs::read(file_path).map_err(|e| format!("Failed to read file: {}", e))?;
    if file_data.len() < 2 {
        return Err("File too short to contain status code".to_string());
    }
    let status_code = u16::from_be_bytes([file_data[0], file_data[1]]);
    let incident_type = match status_code {
        0x0000 => "Clean",
        0x0F2E => "Handoff Conflict",
        0x0E1A => "Race Condition",
        0x0D44 => "Orphaned Step",
        0x1A4F => "Transaction Replay",
        0x1B88 => "Schema Mutation",
        0x1C2B => "Log Truncation",
        0x2A90 => "Packet Modification",
        0x2B11 => "Timestamp Drift",
        0x2C7F => "API Spoofing",
        0x3A01 => "Prompt Injection",
        0x3B99 => "Entropy Leakage",
        0x3C4D => "Register Forgery",
        _ => "Unknown Incident",
    };
    Ok(TriageAnalysis::new(file_path, status_code, incident_type))
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("gemini_test_{}_{}", prefix, std::process::id()));
        fs::create_dir_all(&path).unwrap();
        TempDir { path }
    }
    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
    fn join_s(&self, name: String) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn write_incident(path: &PathBuf, code: u16, payload: &[u8]) {
    let mut data = code.to_be_bytes().to_vec();
    data.extend_from_slice(payload);
    fs::write(path, &data).unwrap();
}

#[test]
fn test_analyze_incident_clean() {
    let tmp = TempDir::new("analyze_clean");
    let path = tmp.join("clean.evkp");
    write_incident(&path, 0x0000, b"clean payload");
    let result = analyze_incident(path.to_str().unwrap()).unwrap();
    assert_eq!(result.raw_code, 0x0000);
    assert_eq!(result.incident_type, "Clean");
    assert!(result.is_valid_safe());
}

#[test]
fn test_analyze_incident_all_malicious_codes() {
    let tmp = TempDir::new("analyze_all_malicious");
    for exp in all_known_codes().into_iter().filter(|e| e.code != 0x0000) {
        let path = tmp.join_s(format!("incident_{:04x}.evkp", exp.code));
        write_incident(&path, exp.code, b"malicious payload");
        let result = analyze_incident(path.to_str().unwrap()).unwrap();
        assert_eq!(result.raw_code, exp.code, "raw_code for 0x{:04X}", exp.code);
        assert_eq!(result.incident_type, exp.incident_type);
        assert_eq!(result.severity, exp.severity);
    }
}

#[test]
fn test_analyze_incident_unknown_code() {
    let tmp = TempDir::new("analyze_unknown");
    let path = tmp.join("unknown.evkp");
    write_incident(&path, 0xBEEF, b"unknown payload");
    let result = analyze_incident(path.to_str().unwrap()).unwrap();
    assert_eq!(result.raw_code, 0xBEEF);
    assert_eq!(result.incident_type, "Unknown Incident");
}

#[test]
fn test_analyze_incident_nonexistent_file() {
    let result = analyze_incident("/nonexistent/file.evkp");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Failed to read file"));
}

#[test]
fn test_analyze_incident_too_short() {
    let tmp = TempDir::new("analyze_short");
    let path = tmp.join("short.evkp");
    fs::write(&path, b"X").unwrap(); // only 1 byte
    let result = analyze_incident(path.to_str().unwrap());
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("too short"));
}

#[test]
fn test_analyze_incident_empty_file() {
    let tmp = TempDir::new("analyze_empty");
    let path = tmp.join("empty.evkp");
    fs::write(&path, b"").unwrap();
    let result = analyze_incident(path.to_str().unwrap());
    assert!(result.is_err());
}

#[test]
fn test_analyze_incident_big_endian_parsing() {
    let tmp = TempDir::new("analyze_endian");
    let path = tmp.join("endian.evkp");
    // 0x0F2E in big-endian = [0x0F, 0x2E]
    write_incident(&path, 0x0F2E, b"");
    let result = analyze_incident(path.to_str().unwrap()).unwrap();
    assert_eq!(result.raw_code, 0x0F2E);
    assert_eq!(result.status_code, "0x0F2E");
}

// ─── gen_fixtures + evk signature verification flow ───────────────────

fn cargo_bin(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push("release");
    path.push(name);
    path
}

#[test]
fn test_gen_fixtures_creates_files() {
    let tmp = TempDir::new("gen_fixtures");
    let output = std::process::Command::new(cargo_bin("gen_fixtures"))
        .current_dir(&tmp.path)
        .output()
        .expect("failed to run gen_fixtures");

    assert!(
        output.status.success(),
        "gen_fixtures failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        tmp.join("test/pubkey.hex").exists(),
        "pubkey.hex not created"
    );
    assert!(tmp.join("job.evk").exists(), "job.evk not created");
    assert!(tmp.join("job.evk.zip").exists(), "job.evk.zip not created");

    // Verify pubkey is 32 bytes in hex (64 chars)
    let pubkey_hex = fs::read_to_string(tmp.join("test/pubkey.hex")).unwrap();
    assert_eq!(pubkey_hex.trim().len(), 64, "pubkey hex should be 64 chars");
    assert!(
        hex::decode(pubkey_hex.trim()).is_ok(),
        "pubkey hex is valid hex"
    );
}

#[test]
fn test_gen_fixtures_zip_contains_expected_entries() {
    let tmp = TempDir::new("gen_fixtures_zip");
    std::process::Command::new(cargo_bin("gen_fixtures"))
        .current_dir(&tmp.path)
        .output()
        .expect("failed to run gen_fixtures");

    let zip_file = fs::File::open(tmp.join("job.evk.zip")).unwrap();
    let mut zip = ZipArchive::new(zip_file).unwrap();

    let mut names: Vec<String> = zip.file_names().map(|n| n.to_string()).collect();
    names.sort();
    assert!(names.contains(&"job.evk".to_string()));
    assert!(names.contains(&"job.evk.sig".to_string()));
    assert_eq!(names.len(), 2);

    // Read job.evk content
    let mut evk_content = Vec::new();
    zip.by_name("job.evk")
        .unwrap()
        .read_to_end(&mut evk_content)
        .unwrap();
    assert!(!evk_content.is_empty());

    // Read signature
    let mut sig_content = Vec::new();
    zip.by_name("job.evk.sig")
        .unwrap()
        .read_to_end(&mut sig_content)
        .unwrap();
    let sig_str = String::from_utf8(sig_content).unwrap();
    let sig_bytes = hex::decode(sig_str.trim()).unwrap();
    assert_eq!(sig_bytes.len(), 64, "ed25519 signature must be 64 bytes");
}

#[test]
fn test_gen_fixtures_is_deterministic_for_same_job_evk() {
    let tmp = TempDir::new("gen_fixtures_det");

    // Create a fixed job.evk first
    let fixed_content = b"fixed job content for determinism test";
    fs::write(tmp.join("job.evk"), fixed_content).unwrap();

    // Run gen_fixtures — it should use the existing job.evk
    let output1 = std::process::Command::new(cargo_bin("gen_fixtures"))
        .current_dir(&tmp.path)
        .output()
        .unwrap();
    assert!(output1.status.success());

    let pubkey1 = fs::read_to_string(tmp.join("test/pubkey.hex")).unwrap();
    let zip1_bytes = fs::read(tmp.join("job.evk.zip")).unwrap();

    // Run again — same job.evk, but new random key
    let output2 = std::process::Command::new(cargo_bin("gen_fixtures"))
        .current_dir(&tmp.path)
        .output()
        .unwrap();
    assert!(output2.status.success());

    let pubkey2 = fs::read_to_string(tmp.join("test/pubkey.hex")).unwrap();

    // Public keys should differ (random key each time)
    assert_ne!(
        pubkey1, pubkey2,
        "each gen_fixtures run should generate a new key"
    );

    // But job.evk content should be unchanged
    let evk = fs::read(tmp.join("job.evk")).unwrap();
    assert_eq!(evk, fixed_content);

    // zip1 and zip2 should differ (different keys/sigs) but both valid zips
    let zip2_bytes = fs::read(tmp.join("job.evk.zip")).unwrap();
    assert_ne!(zip1_bytes, zip2_bytes, "zips should differ due to new key");
}

// ─── E01Reader placeholder tests ──────────────────────────────────────

#[test]
fn test_e01_reader_not_implemented() {
    // E01Reader::open always returns Err — verify this contract
    // We can't import it directly (it's a bin), so we test via subprocess
    let output = std::process::Command::new(cargo_bin("e01_extract"))
        .arg("/nonexistent/image.E01")
        .output()
        .expect("failed to run e01_extract");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("not yet implemented") || stdout.contains("E01Reader"));
}

#[test]
fn test_e01_extract_no_args_exits_nonzero() {
    let output = std::process::Command::new(cargo_bin("e01_extract"))
        .output()
        .expect("failed to run e01_extract");
    assert!(
        !output.status.success(),
        "should exit non-zero with no args"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Usage") || stderr.contains("usage"));
}

// ─── evk binary (signature verifier) tests ────────────────────────────

#[test]
fn test_evk_binary_missing_zip_fails() {
    let tmp = TempDir::new("evk_no_zip");
    let output = std::process::Command::new(cargo_bin("evk"))
        .current_dir(&tmp.path)
        .output()
        .expect("failed to run evk");

    // Should fail because job.evk.zip doesn't exist
    assert!(!output.status.success());
}

// Helper trait for test ergonomics
trait ValidityHelper {
    fn is_valid_safe(&self) -> bool;
}

impl ValidityHelper for TriageAnalysis {
    fn is_valid_safe(&self) -> bool {
        self.raw_code == 0x0000
    }
}
