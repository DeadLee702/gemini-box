use serde::{Deserialize, Serialize};
use std::fs;

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
            0x0000 => (
                1.0,
                "Bundle verified as clean. No malicious artifacts detected.".to_string(),
                "allow".to_string(),
                "LOW".to_string(),
            ),
            0x0F2E => (
                0.95,
                "Handoff conflict detected: Step executed by wrong actor. \
                 Indicates role-based access control violation or process orchestration failure."
                    .to_string(),
                "block".to_string(),
                "HIGH".to_string(),
            ),
            0x0E1A => (
                0.92,
                "Race condition detected: Concurrent modification without proper synchronization. \
                 May indicate state corruption or timing-based vulnerability."
                    .to_string(),
                "quarantine".to_string(),
                "HIGH".to_string(),
            ),
            0x0D44 => (
                0.90,
                "Orphaned step detected: Process step with no parent/owner. \
                 Indicates incomplete workflow state or dangling process."
                    .to_string(),
                "escalate".to_string(),
                "MEDIUM".to_string(),
            ),
            0x1A4F => (
                0.98,
                "Transaction replay attack detected: Prior transaction re-executed. \
                 Critical security incident indicating attacker replay capability."
                    .to_string(),
                "block".to_string(),
                "CRITICAL".to_string(),
            ),
            0x1B88 => (
                0.88,
                "Schema mutation detected: Unexpected data structure change. \
                 May indicate tampering, version mismatch, or injection attack."
                    .to_string(),
                "quarantine".to_string(),
                "MEDIUM".to_string(),
            ),
            0x1C2B => (
                0.96,
                "Log truncation detected: Critical audit trail entries removed. \
                 Indicates deliberate evidence destruction or forensic tampering."
                    .to_string(),
                "escalate".to_string(),
                "CRITICAL".to_string(),
            ),
            0x2A90 => (
                0.94,
                "Packet modification detected: In-transit data tampering. \
                 Network layer compromise or man-in-the-middle attack suspected."
                    .to_string(),
                "block".to_string(),
                "HIGH".to_string(),
            ),
            0x2B11 => (
                0.85,
                "Timestamp drift detected: Significant clock skew detected. \
                 May indicate system compromise, timezone misconfiguration, or temporal attack."
                    .to_string(),
                "escalate".to_string(),
                "MEDIUM".to_string(),
            ),
            0x2C7F => (
                0.97,
                "API spoofing detected: Impersonated service endpoint. \
                 Attacker intercepted or redirected API calls to malicious endpoint."
                    .to_string(),
                "block".to_string(),
                "CRITICAL".to_string(),
            ),
            0x3A01 => (
                0.91,
                "Prompt injection detected: Malicious input to LLM/system command interface. \
                 Attacker attempted to manipulate system behavior through user input."
                    .to_string(),
                "quarantine".to_string(),
                "HIGH".to_string(),
            ),
            0x3B99 => (
                0.99,
                "Entropy leakage detected: Cryptographic material exposed. \
                 CRITICAL: Cryptographic keys or random seeds may have been compromised."
                    .to_string(),
                "escalate".to_string(),
                "CRITICAL".to_string(),
            ),
            0x3C4D => (
                0.93,
                "Register forgery detected: Tampered hardware/software register state. \
                 Indicates low-level compromise or hardware-level attack."
                    .to_string(),
                "block".to_string(),
                "CRITICAL".to_string(),
            ),
            _ => (
                0.70,
                format!(
                    "Unknown malicious status code detected: 0x{:04X}. \
                     Recommend manual review and forensic investigation.",
                    status_code
                ),
                "escalate".to_string(),
                "MEDIUM".to_string(),
            ),
        }
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

pub fn analyze_incident(file_path: &str) -> Result<TriageAnalysis, String> {
    let file_data = fs::read(file_path).map_err(|e| format!("Failed to read file: {}", e))?;

    if file_data.len() < 2 {
        return Err("File too short to contain status code".to_string());
    }

    let status_code = u16::from_be_bytes([file_data[0], file_data[1]]);

    let incident_type = match status_code {
        0x0000 => "Clean".to_string(),
        0x0F2E => "Handoff Conflict".to_string(),
        0x0E1A => "Race Condition".to_string(),
        0x0D44 => "Orphaned Step".to_string(),
        0x1A4F => "Transaction Replay".to_string(),
        0x1B88 => "Schema Mutation".to_string(),
        0x1C2B => "Log Truncation".to_string(),
        0x2A90 => "Packet Modification".to_string(),
        0x2B11 => "Timestamp Drift".to_string(),
        0x2C7F => "API Spoofing".to_string(),
        0x3A01 => "Prompt Injection".to_string(),
        0x3B99 => "Entropy Leakage".to_string(),
        0x3C4D => "Register Forgery".to_string(),
        _ => "Unknown Incident".to_string(),
    };

    Ok(TriageAnalysis::new(file_path, status_code, incident_type))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_artifact_classification() {
        let analysis = TriageAnalysis::new("test.evkp", 0x0000, "Clean");
        assert_eq!(analysis.confidence, 1.0);
        assert_eq!(analysis.recommended_action, "allow");
        assert_eq!(analysis.severity, "LOW");
    }

    #[test]
    fn test_prompt_injection_classification() {
        let analysis = TriageAnalysis::new("test.evkp", 0x3A01, "Prompt Injection");
        assert_eq!(analysis.confidence, 0.91);
        assert_eq!(analysis.recommended_action, "quarantine");
        assert_eq!(analysis.severity, "HIGH");
    }

    #[test]
    fn test_entropy_leakage_classification() {
        let analysis = TriageAnalysis::new("test.evkp", 0x3B99, "Entropy Leakage");
        assert_eq!(analysis.confidence, 0.99);
        assert_eq!(analysis.recommended_action, "escalate");
        assert_eq!(analysis.severity, "CRITICAL");
    }

    #[test]
    fn test_json_serialization() {
        let analysis = TriageAnalysis::new("test.evkp", 0x1A4F, "Transaction Replay");
        let json = analysis.to_json().expect("JSON serialization failed");
        assert!(json.contains("0x1A4F"));
        assert!(json.contains("Transaction Replay"));
    }
}
