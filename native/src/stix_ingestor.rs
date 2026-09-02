use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixIndicator {
    pub id: String,
    #[serde(rename = "type")]
    pub stix_type: String,
    pub name: String,
    pub description: Option<String>,
    pub pattern: String,
    pub pattern_type: String,
    pub valid_from: String,
    pub confidence: Option<u32>,
    pub labels: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixBundle {
    #[serde(rename = "type")]
    pub bundle_type: String,
    pub id: String,
    pub objects: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct StixIngestRequest {
    pub bundle_json: Option<String>,
    pub feed_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StixIngestResponse {
    pub success: bool,
    pub total_indicators_extracted: usize,
    pub indicators: Vec<StixIndicator>,
    pub message: String,
}

pub struct StixIngestor;

impl StixIngestor {
    pub fn parse_bundle(json_str: &str) -> Result<Vec<StixIndicator>, String> {
        let bundle: StixBundle = serde_json::from_str(json_str)
            .map_err(|e| format!("Invalid STIX 2.1 Bundle JSON: {}", e))?;

        let mut indicators = Vec::new();

        for obj in bundle.objects {
            if obj.get("type").and_then(|t| t.as_str()) == Some("indicator") {
                if let Ok(ind) = serde_json::from_value::<StixIndicator>(obj) {
                    indicators.push(ind);
                }
            }
        }

        Ok(indicators)
    }

    pub fn sample_cisa_stix_bundle() -> String {
        serde_json::json!({
            "type": "bundle",
            "id": "bundle--c02d8478-f7ef-489e-9d2d-d558b8f21915",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                    "name": "Log4j JNDI Exploit String Indicator",
                    "description": "Matches inbound HTTP requests attempting JNDI LDAP lookup injection",
                    "pattern": "[network-traffic:dst_payload_ref.value MATCHES '\\$\\{jndi:(ldap|rmi|dns):']",
                    "pattern_type": "stix",
                    "valid_from": "2021-12-10T00:00:00Z",
                    "confidence": 95,
                    "labels": ["malicious-activity", "rce", "cve-2021-44228"]
                },
                {
                    "type": "indicator",
                    "id": "indicator--9f3f3e3c-28e5-5dcf-049a-09ff57c4de4a",
                    "name": "Cobalt Strike Beacon HTTP Header",
                    "description": "Identifies HTTP requests matching known Cobalt Strike malleable C2 profiles",
                    "pattern": "[http-request:headers.'User-Agent' = 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)']",
                    "pattern_type": "stix",
                    "valid_from": "2023-01-15T00:00:00Z",
                    "confidence": 90,
                    "labels": ["c2", "cobalt-strike"]
                },
                {
                    "type": "indicator",
                    "id": "indicator--aa4a4e4d-39f6-6edf-150b-10aa68d5ef5b",
                    "name": "XZ Utils Backdoor Liblzma Checksum",
                    "description": "Compromised liblzma.so SHA-256 binary hash",
                    "pattern": "[file:hashes.'SHA-256' = '4d0362f6b8b0e60d0092ad81ffc6198f6834d852cb7805128ff093952f9547d0']",
                    "pattern_type": "stix",
                    "valid_from": "2024-03-29T00:00:00Z",
                    "confidence": 100,
                    "labels": ["supply-chain", "backdoor", "cve-2024-3094"]
                }
            ]
        }).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stix_bundle_parsing() {
        let bundle_json = StixIngestor::sample_cisa_stix_bundle();
        let indicators = StixIngestor::parse_bundle(&bundle_json).expect("Should parse bundle");
        assert_eq!(indicators.len(), 3);
        assert!(indicators[0].name.contains("Log4j"));
        assert!(indicators[1].name.contains("Cobalt Strike"));
        assert!(indicators[2].name.contains("XZ Utils"));
    }
}
