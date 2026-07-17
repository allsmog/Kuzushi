use kuzushi_core::RunTargetGitMetadata;
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScreenContext {
    pub(crate) view: String,
    pub(crate) focused_pane: Option<String>,
    pub(crate) selected_item: Option<ScreenSelectedItem>,
    pub(crate) selected_run: Option<String>,
    pub(crate) selected_revision: Option<ScreenRevision>,
    pub(crate) active_phase: Option<String>,
    pub(crate) active_filters: Vec<String>,
    pub(crate) selected_scope: Option<String>,
    pub(crate) finding_summary: Option<ScreenFindingSummary>,
    pub(crate) visible_rows: Vec<String>,
    pub(crate) cursor: ScreenCursor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScreenSelectedItem {
    pub(crate) alias: Option<String>,
    pub(crate) fingerprint: String,
    pub(crate) title: String,
    pub(crate) file: String,
    pub(crate) line: u32,
    pub(crate) rank: String,
    pub(crate) state: String,
    pub(crate) runtime_verification: String,
    pub(crate) triage: Option<ScreenTriageContext>,
    pub(crate) proof: ScreenProofContext,
    pub(crate) evidence: Vec<ScreenEvidenceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScreenTriageContext {
    pub(crate) verdict: String,
    pub(crate) confidence: String,
    pub(crate) rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScreenProofContext {
    pub(crate) static_label: String,
    pub(crate) static_explanation: String,
    pub(crate) runtime_label: String,
    pub(crate) runtime_explanation: String,
    pub(crate) verification: Option<ScreenVerificationContext>,
    pub(crate) next_action: String,
    pub(crate) next_command: Option<String>,
    pub(crate) next_detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScreenVerificationContext {
    pub(crate) verdict: String,
    pub(crate) proof_level: u8,
    pub(crate) backend: String,
    pub(crate) language: Option<String>,
    pub(crate) harness: Option<String>,
    pub(crate) crash_evidence: Option<String>,
    pub(crate) notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScreenEvidenceContext {
    pub(crate) kind: String,
    pub(crate) file: String,
    pub(crate) line: u32,
    pub(crate) confidence: u8,
    pub(crate) snippet: String,
    pub(crate) rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScreenFindingSummary {
    pub(crate) total: usize,
    pub(crate) by_severity: Vec<ScreenCount>,
    pub(crate) by_verdict: Vec<ScreenCount>,
    pub(crate) by_proof_state: Vec<ScreenCount>,
    pub(crate) runtime_proof_by_severity: Vec<ScreenCount>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScreenCount {
    pub(crate) label: String,
    pub(crate) count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScreenRevision {
    pub(crate) sha: String,
    pub(crate) branch: Option<String>,
    pub(crate) dirty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScreenCursor {
    pub(crate) row: usize,
    pub(crate) col: usize,
}

impl ScreenContext {
    pub(crate) fn to_prompt_json(&self) -> String {
        serde_json::to_string_pretty(&self.as_json_value()).unwrap_or_else(|_| "{}".to_string())
    }

    pub(crate) fn scope_chip(&self) -> Option<String> {
        let mut parts = Vec::new();
        push_primary_scope_part(&mut parts, self);
        if let Some(phase) = self.active_phase.as_deref() {
            parts.push(active_phase_chip(phase));
        }
        if let Some(revision) = &self.selected_revision {
            parts.push(revision.short_label());
        }
        (!parts.is_empty()).then(|| format!("scope: {}", parts.join(" · ")))
    }

    fn as_json_value(&self) -> Value {
        json!({
            "view": self.view,
            "focusedPane": self.focused_pane,
            "selectedItem": self.selected_item.as_ref().map(ScreenSelectedItem::as_json_value),
            "selectedRun": self.selected_run,
            "selectedRevision": self.selected_revision.as_ref().map(ScreenRevision::as_json_value),
            "activePhase": self.active_phase,
            "activeFilters": self.active_filters,
            "selectedScope": self.selected_scope,
            "scopeLabel": self.scope_chip(),
            "findingSummary": self.finding_summary.as_ref().map(ScreenFindingSummary::as_json_value),
            "visibleRows": self.visible_rows,
            "cursor": {
                "row": self.cursor.row,
                "col": self.cursor.col,
            },
        })
    }
}

impl ScreenSelectedItem {
    fn as_json_value(&self) -> Value {
        json!({
            "alias": self.alias,
            "fingerprint": self.fingerprint,
            "title": self.title,
            "file": self.file,
            "line": self.line,
            "rank": self.rank,
            "state": self.state,
            "runtimeVerification": self.runtime_verification,
            "triage": self.triage.as_ref().map(ScreenTriageContext::as_json_value),
            "proof": self.proof.as_json_value(),
            "evidence": self
                .evidence
                .iter()
                .map(ScreenEvidenceContext::as_json_value)
                .collect::<Vec<_>>(),
        })
    }
}

impl ScreenTriageContext {
    fn as_json_value(&self) -> Value {
        json!({
            "verdict": self.verdict,
            "confidence": self.confidence,
            "rationale": self.rationale,
        })
    }
}

impl ScreenProofContext {
    fn as_json_value(&self) -> Value {
        json!({
            "staticLabel": self.static_label,
            "staticExplanation": self.static_explanation,
            "runtimeLabel": self.runtime_label,
            "runtimeExplanation": self.runtime_explanation,
            "verification": self.verification.as_ref().map(ScreenVerificationContext::as_json_value),
            "nextAction": self.next_action,
            "nextCommand": self.next_command,
            "nextDetail": self.next_detail,
        })
    }
}

impl ScreenVerificationContext {
    fn as_json_value(&self) -> Value {
        json!({
            "verdict": self.verdict,
            "proofLevel": self.proof_level,
            "backend": self.backend,
            "language": self.language,
            "harness": self.harness,
            "crashEvidence": self.crash_evidence,
            "notes": self.notes,
        })
    }
}

impl ScreenEvidenceContext {
    fn as_json_value(&self) -> Value {
        json!({
            "kind": self.kind,
            "file": self.file,
            "line": self.line,
            "confidence": self.confidence,
            "snippet": self.snippet,
            "rationale": self.rationale,
        })
    }
}

impl ScreenFindingSummary {
    fn as_json_value(&self) -> Value {
        json!({
            "total": self.total,
            "bySeverity": count_values(&self.by_severity),
            "byVerdict": count_values(&self.by_verdict),
            "byProofState": count_values(&self.by_proof_state),
            "runtimeProofBySeverity": count_values(&self.runtime_proof_by_severity),
        })
    }
}

impl ScreenCount {
    fn as_json_value(&self) -> Value {
        json!({
            "label": self.label,
            "count": self.count,
        })
    }
}

impl ScreenRevision {
    fn as_json_value(&self) -> Value {
        json!({
            "sha": self.sha,
            "branch": self.branch,
            "dirty": self.dirty,
        })
    }

    fn short_label(&self) -> String {
        let mut label = self.sha.chars().take(7).collect::<String>();
        if self.dirty {
            label.push_str("-dirty");
        }
        label
    }
}

impl From<RunTargetGitMetadata> for ScreenRevision {
    fn from(metadata: RunTargetGitMetadata) -> Self {
        Self {
            sha: metadata.sha,
            branch: metadata.branch,
            dirty: metadata.dirty,
        }
    }
}

fn count_values(values: &[ScreenCount]) -> Vec<Value> {
    values.iter().map(ScreenCount::as_json_value).collect()
}

fn push_primary_scope_part(parts: &mut Vec<String>, context: &ScreenContext) {
    if let Some(item) = &context.selected_item {
        parts.push(selected_item_scope_label(item));
    } else if let Some(scope) = &context.selected_scope {
        parts.push(scope.clone());
    }
}

fn selected_item_scope_label(item: &ScreenSelectedItem) -> String {
    item.alias
        .clone()
        .unwrap_or_else(|| item.fingerprint.chars().take(12).collect())
}

fn active_phase_chip(phase: &str) -> String {
    match phase {
        "map" => "組 map",
        "scan" | "hunt" => "崩 scan",
        "review" => "査 review",
        "prove" | "confirm" => "作 prove",
        "fix" => "掛 fix",
        other => other,
    }
    .to_string()
}
