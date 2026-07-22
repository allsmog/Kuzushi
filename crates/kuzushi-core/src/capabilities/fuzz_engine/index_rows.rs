//! Tolerant parse + fold of AFE's `data/findings-index.jsonl`.
//!
//! The index is an append-only event stream (`recorded` / `classified` /
//! `graded` / `deduped` / `impact` / `reachability` rows). Import wants the
//! fold view: latest recorded state per `finding_id`, with the impact pass's
//! primitive/write-evidence verdicts joined on. Rows that fail to parse are
//! counted, never fatal (mirrors the ledger importer contract).

use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct RecordedRow {
    pub finding_id: String,
    pub run_id: String,
    pub target: String,
    pub harness: String,
    pub sanitizer: String,
    pub error_token: String,
    pub signature: String,
    pub root_signature: String,
    pub crash_state: Vec<String>,
    pub primitive: Option<String>,
    pub poc_artifact: Option<String>,
    pub poc_sha256: Option<String>,
    pub poc_size: Option<u64>,
    pub reproductions: u64,
    pub verified: bool,
    pub crash_excerpt: String,
}

#[derive(Debug, Clone)]
pub enum IndexEvent {
    Recorded(Box<RecordedRow>),
    Impact {
        finding_id: String,
        primitive: Option<String>,
        write_evidence: bool,
    },
    Other,
}

/// One finding after the fold: its latest recorded state plus any impact
/// verdicts that arrived later in the stream.
#[derive(Debug, Clone)]
pub struct FoldedFinding {
    pub recorded: RecordedRow,
    pub impact_primitive: Option<String>,
    pub write_evidence: bool,
}

impl FoldedFinding {
    /// The impact pass replays the PoV under instrumentation, so its verdict
    /// outranks the primitive guessed at record time.
    pub fn effective_primitive(&self) -> Option<&str> {
        self.impact_primitive
            .as_deref()
            .or(self.recorded.primitive.as_deref())
    }
}

pub fn parse_and_fold(body: &str) -> (Vec<FoldedFinding>, usize) {
    let mut folded: Vec<FoldedFinding> = Vec::new();
    let mut skipped = 0usize;
    for line in body.lines().map(str::trim).filter(|line| !line.is_empty()) {
        match parse_index_line(line) {
            Some(event) => apply_event(&mut folded, event),
            None => skipped += 1,
        }
    }
    (folded, skipped)
}

fn apply_event(folded: &mut Vec<FoldedFinding>, event: IndexEvent) {
    match event {
        IndexEvent::Recorded(row) => apply_recorded(folded, *row),
        IndexEvent::Impact {
            finding_id,
            primitive,
            write_evidence,
        } => {
            if let Some(entry) = folded
                .iter_mut()
                .find(|entry| entry.recorded.finding_id == finding_id)
            {
                entry.impact_primitive = primitive;
                entry.write_evidence = write_evidence;
            }
        }
        IndexEvent::Other => {}
    }
}

fn apply_recorded(folded: &mut Vec<FoldedFinding>, row: RecordedRow) {
    if let Some(entry) = folded
        .iter_mut()
        .find(|entry| entry.recorded.finding_id == row.finding_id)
    {
        entry.recorded = row;
        return;
    }
    folded.push(FoldedFinding {
        recorded: row,
        impact_primitive: None,
        write_evidence: false,
    });
}

pub fn parse_index_line(line: &str) -> Option<IndexEvent> {
    let value: Value = serde_json::from_str(line).ok()?;
    let object = value.as_object()?;
    match object.get("event").and_then(Value::as_str)? {
        "recorded" => Some(IndexEvent::Recorded(Box::new(recorded_row(object)?))),
        "impact" => impact_event(object),
        _ => Some(IndexEvent::Other),
    }
}

fn recorded_row(object: &serde_json::Map<String, Value>) -> Option<RecordedRow> {
    let finding_id = non_empty(object, "finding_id")?;
    Some(RecordedRow {
        finding_id,
        run_id: string_field(object, "run_id"),
        target: string_field(object, "target"),
        harness: string_field(object, "harness"),
        sanitizer: string_field(object, "sanitizer"),
        error_token: string_field(object, "error_token"),
        signature: string_field(object, "signature"),
        root_signature: string_field(object, "root_signature"),
        crash_state: string_list(object.get("crash_state")),
        primitive: object
            .get("primitive")
            .and_then(Value::as_str)
            .map(str::to_string),
        poc_artifact: object
            .get("poc_artifact")
            .and_then(Value::as_str)
            .map(str::to_string),
        poc_sha256: object
            .get("poc_sha256")
            .and_then(Value::as_str)
            .map(str::to_string),
        poc_size: object.get("poc_size").and_then(Value::as_u64),
        reproductions: object
            .get("reproductions")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        verified: object
            .get("verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        crash_excerpt: string_field(object, "crash_excerpt"),
    })
}

fn impact_event(object: &serde_json::Map<String, Value>) -> Option<IndexEvent> {
    let finding_id = non_empty(object, "finding_id")?;
    let detail = object.get("detail").and_then(Value::as_object);
    let primitive = detail
        .and_then(|detail| detail.get("primitive"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let write_evidence = detail
        .and_then(|detail| detail.get("write_evidence"))
        .is_some_and(write_evidence_flag);
    Some(IndexEvent::Impact {
        finding_id,
        primitive,
        write_evidence,
    })
}

/// The impact pass reports write evidence as a descriptive string (`"none"`
/// when the oracle saw nothing); older payloads used a bool.
pub(crate) fn write_evidence_flag(value: &Value) -> bool {
    match value {
        Value::Bool(flag) => *flag,
        Value::String(text) => !text.trim().is_empty() && text.trim() != "none",
        _ => false,
    }
}

fn non_empty(object: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn string_field(object: &serde_json::Map<String, Value>, key: &str) -> String {
    non_empty(object, key).unwrap_or_default()
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORDED: &str = r#"{"event":"recorded","finding_id":"finding-aa","run_id":"r1","target":"vhdx","harness":"vhdx_open","sanitizer":"address","error_token":"AddressSanitizer: heap-buffer-overflow","signature":"sig1","root_signature":"root1","crash_state":["ns::Parse(unsigned","ns::Open"],"primitive":"read","poc_artifact":"pov.bin","poc_sha256":"ab12","poc_size":18,"reproductions":3,"verified":true,"crash_excerpt":"INFO: Seed"}"#;

    #[test]
    fn fold_joins_latest_recorded_state_with_impact_verdicts() {
        let body = format!(
            "{RECORDED}\n{}\n{}\n{}\nnot-json\n",
            r#"{"event":"deduped","finding_id":"finding-aa","detail":{"groups":1}}"#,
            r#"{"event":"recorded","finding_id":"finding-aa","run_id":"r2","target":"vhdx","harness":"vhdx_open","sanitizer":"address","error_token":"AddressSanitizer: heap-buffer-overflow","signature":"sig1","root_signature":"root1","reproductions":5,"verified":true}"#,
            r#"{"event":"impact","finding_id":"finding-aa","detail":{"primitive":"write","write_evidence":"asan shadow write at +0x10"}}"#,
        );

        let (folded, skipped) = parse_and_fold(&body);

        assert_eq!(skipped, 1);
        assert_eq!(folded.len(), 1);
        let entry = &folded[0];
        assert_eq!(entry.recorded.run_id, "r2", "later recorded row wins");
        assert_eq!(entry.recorded.reproductions, 5);
        assert_eq!(entry.effective_primitive(), Some("write"));
        assert!(entry.write_evidence);
    }

    #[test]
    fn impact_write_evidence_none_is_false_and_recorded_primitive_is_fallback() {
        let body = format!(
            "{RECORDED}\n{}\n",
            r#"{"event":"impact","finding_id":"finding-aa","detail":{"primitive":null,"write_evidence":"none"}}"#,
        );

        let (folded, _) = parse_and_fold(&body);

        assert_eq!(folded[0].effective_primitive(), Some("read"));
        assert!(!folded[0].write_evidence);
    }

    #[test]
    fn rows_without_finding_id_or_json_are_counted_skipped() {
        let (folded, skipped) =
            parse_and_fold("{\"event\":\"recorded\"}\n{}\ngarbage\n");
        assert!(folded.is_empty());
        assert_eq!(skipped, 3);
    }
}
