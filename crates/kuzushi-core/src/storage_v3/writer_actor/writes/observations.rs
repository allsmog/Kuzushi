use crate::identity::{
    compute_observation_hash_v3, compute_stable_fp_v3, hash_parts, ObservationHashInput,
    StableFindingInput,
};
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationWrite {
    pub projected_finding_id: Option<i64>,
    pub identity_id: Option<String>,
    pub identity_alias: Option<String>,
    pub identity_fingerprint: Option<String>,
    pub identity_match_basis: Option<String>,
    pub observation_hash: String,
    pub stable_fp: String,
    pub snapshot_hash: String,
    pub run_id: String,
    pub tool: String,
    pub tool_version: Option<String>,
    pub rule_id: String,
    pub rule_set_hash: Option<String>,
    pub severity: String,
    pub title: String,
    pub message: String,
    pub blob_hash: Option<String>,
    pub byte_start: Option<u64>,
    pub byte_end: Option<u64>,
    pub display_path: Option<String>,
    pub display_line: Option<u32>,
    pub raw_result_hash: String,
    pub finding_json: Option<String>,
    pub actor: String,
}

impl ObservationWrite {
    pub(in crate::storage_v3::writer_actor) fn payload(&self) -> Value {
        json!({
            "projectedFindingId": self.projected_finding_id,
            "identityId": self.identity_id,
            "identityAlias": self.identity_alias,
            "identityFingerprint": self.identity_fingerprint,
            "identityMatchBasis": self.identity_match_basis,
            "observationHash": self.observation_hash,
            "stableFp": self.stable_fp,
            "snapshotHash": self.snapshot_hash,
            "runId": self.run_id,
            "tool": self.tool,
            "toolVersion": self.tool_version,
            "ruleId": self.rule_id,
            "ruleSetHash": self.rule_set_hash,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "blobHash": self.blob_hash,
            "byteStart": self.byte_start,
            "byteEnd": self.byte_end,
            "displayPath": self.display_path,
            "displayLine": self.display_line,
            "rawResultHash": self.raw_result_hash,
            "findingJson": self.finding_json,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateObservationWrite {
    pub snapshot_hash: String,
    pub run_id: String,
    pub tool: String,
    pub tool_version: Option<String>,
    pub rule_id: String,
    pub rule_set_hash: Option<String>,
    pub severity: String,
    pub title: String,
    pub message: String,
    pub blob_hash: String,
    pub byte_start: u64,
    pub byte_end: u64,
    pub display_path: Option<String>,
    pub display_line: Option<u32>,
    pub language: Option<String>,
    pub normalized_snippet: String,
    pub local_context_hash: Option<String>,
    pub raw_result_json: String,
    pub actor: String,
}

impl CandidateObservationWrite {
    pub(in crate::storage_v3::writer_actor) fn into_observation_write(self) -> ObservationWrite {
        let raw_result_hash = self.raw_result_hash();
        let stable_fp = self.stable_fp();
        let observation_hash = self.observation_hash(&raw_result_hash);
        ObservationWrite {
            projected_finding_id: None,
            identity_id: None,
            identity_alias: None,
            identity_fingerprint: None,
            identity_match_basis: None,
            observation_hash,
            stable_fp,
            snapshot_hash: self.snapshot_hash,
            run_id: self.run_id,
            tool: self.tool,
            tool_version: self.tool_version,
            rule_id: self.rule_id,
            rule_set_hash: self.rule_set_hash,
            severity: self.severity,
            title: self.title,
            message: self.message,
            blob_hash: Some(self.blob_hash),
            byte_start: Some(self.byte_start),
            byte_end: Some(self.byte_end),
            display_path: self.display_path,
            display_line: self.display_line,
            raw_result_hash,
            finding_json: None,
            actor: self.actor,
        }
    }

    fn stable_fp(&self) -> String {
        compute_stable_fp_v3(StableFindingInput {
            tool_family: &self.tool,
            rule_id: &self.rule_id,
            language: self.language.as_deref(),
            parser_version: None,
            normalizer_version: Some("kuzushi-plugin-sandbox-v3"),
            symbol_path_or_rename_group: self.display_path.as_deref(),
            ast_locus_hash: None,
            normalized_snippet: &self.normalized_snippet,
            local_context_hash: self.local_context_hash.as_deref(),
            disambiguator: None,
        })
    }

    fn raw_result_hash(&self) -> String {
        hash_parts("finding-raw-result", &[self.raw_result_json.as_bytes()])
            .as_str()
            .to_string()
    }

    fn observation_hash(&self, raw_result_hash: &str) -> String {
        compute_observation_hash_v3(ObservationHashInput {
            run_id: &self.run_id,
            tool_name: &self.tool,
            tool_version: self.tool_version.as_deref(),
            rule_set_hash: self.rule_set_hash.as_deref(),
            snapshot_hash: Some(&self.snapshot_hash),
            raw_result_hash,
        })
    }
}
