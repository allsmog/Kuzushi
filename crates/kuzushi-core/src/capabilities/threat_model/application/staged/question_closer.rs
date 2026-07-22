use super::super::*;
use super::research::{project_docs_section, read_project_docs};

const MAX_QUESTIONS: usize = 12;
const MAX_PROMPT_ANCHORS: usize = 80;
const MAX_PROMPT_THREATS: usize = 40;

pub(crate) struct QuestionCloserOutcome {
    pub(crate) questions_closed: usize,
    pub(crate) questions_open: usize,
    pub(crate) cost_usd: f64,
    pub(crate) cost_usd_exact: bool,
    pub(crate) method: &'static str,
}

impl QuestionCloserOutcome {
    pub(crate) fn skipped(method: &'static str, questions_open: usize) -> Self {
        Self {
            questions_closed: 0,
            questions_open,
            cost_usd: 0.0,
            cost_usd_exact: true,
            method,
        }
    }
}

/// Refine stage R2: ONE bounded structured call that tries to answer the
/// persisted model's open questions from grounded evidence. The fold is
/// deterministic — an answer closes a question only when it cites at least
/// one evidence ref present in the research index; everything else stays
/// open with a warning instead of shipping unverifiable claims.
pub(crate) fn run_question_closer(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    input: &BuildInput,
    evidence_index: &BTreeSet<String>,
    document: &mut Value,
) -> Result<QuestionCloserOutcome> {
    let questions = open_question_texts(document);
    if questions.is_empty() {
        return Ok(QuestionCloserOutcome::skipped("none-needed", 0));
    }
    let prompt = question_closer_prompt(input, &questions, evidence_index, document);
    let costed = query_question_closer(runtime, ctx, input, verb, questions.len(), prompt)?;
    let questions_closed = fold_answered_questions(document, &costed.value, evidence_index);
    Ok(QuestionCloserOutcome {
        questions_closed,
        questions_open: open_question_texts(document).len(),
        cost_usd: costed.cost_usd,
        cost_usd_exact: costed.cost_usd_exact,
        method: "structured-llm",
    })
}

pub(crate) fn open_question_texts(document: &Value) -> Vec<String> {
    document
        .get("openQuestions")
        .and_then(Value::as_array)
        .map(|rows| rows.iter().filter_map(open_question_text).collect())
        .unwrap_or_default()
}

fn open_question_text(row: &Value) -> Option<String> {
    let text = match row {
        Value::String(text) => text.as_str(),
        Value::Object(fields) => fields.get("question").and_then(Value::as_str)?,
        _ => return None,
    };
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

fn query_question_closer(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    input: &BuildInput,
    verb: &str,
    question_count: usize,
    prompt: String,
) -> Result<crate::structured_output::CostedStructuredJson<Value>> {
    let _scope = begin_question_closer_scope(ctx, verb, question_count);
    let cache = crate::semantic_cache::SemanticCache::open_for_target(&input.target);
    crate::structured_output::query_cached_structured_json_with_cost(
        cache.as_ref(),
        runtime,
        AgentQueryRequest::new(
            input.model.clone(),
            input.target.clone(),
            threat_model_system_prompt(),
            prompt,
        ),
        StructuredJsonContract::new(
            "threat-model:build",
            "ThreatModelQuestionCloser",
            question_closer_schema(),
        ),
        Ok,
    )
    .map(|cached| cached.costed)
}

fn begin_question_closer_scope(
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    question_count: usize,
) -> Option<crate::run_artifacts::ParentScope> {
    ctx.trace.map(|trace| {
        let phase = trace
            .step(
                "reasoning",
                verb,
                format!("question-closer: {question_count} open questions"),
            )
            .emit();
        trace.parent_scope(phase)
    })
}

fn question_closer_schema() -> Value {
    json!({
        "type": "object",
        "required": ["answered", "unanswered"],
        "additionalProperties": false,
        "properties": {
            "answered": {"type": "array", "items": {"type": "object"}},
            "unanswered": {"type": "array", "items": {}}
        }
    })
}

fn question_closer_prompt(
    input: &BuildInput,
    questions: &[String],
    evidence_index: &BTreeSet<String>,
    document: &Value,
) -> String {
    let question_lines = bullet_lines(questions.iter().take(MAX_QUESTIONS).cloned());
    let anchor_lines = bullet_lines(evidence_index.iter().take(MAX_PROMPT_ANCHORS).cloned());
    let threat_lines = bullet_lines(prompt_threat_rows(document));
    let docs = project_docs_section(&read_project_docs(&input.target));
    format!(
        r#"The persisted threat model for {repo} carries open questions from earlier builds. Answer ONLY the questions you can ground in the evidence below; leave every other question unanswered.

Open questions:
{question_lines}

Citable evidence anchors — every evidenceRefs entry MUST be copied verbatim from this list:
{anchor_lines}

Threats in the model (for foldInto="controls", threatStableId MUST be one of these stable ids):
{threat_lines}

{docs}

Return one JSON object:
{{"answered": [{{"question": "<verbatim question text>", "answer": "<grounded answer>", "evidenceRefs": ["<anchor>"], "foldInto": "controls"|"context", "threatStableId": "<stable id, controls only>"}}], "unanswered": ["<verbatim question text>"]}}

Rules:
- An answer with no citable anchor is not an answer; put the question in unanswered.
- foldInto="controls" only when the answer establishes an existing mitigation on a specific threat; otherwise use "context".
- Do not invent files, mitigations, or architecture."#,
        repo = input.repo_name,
    )
}

fn bullet_lines(items: impl Iterator<Item = String>) -> String {
    let lines = items
        .map(|item| format!("- {item}"))
        .collect::<Vec<_>>()
        .join("\n");
    if lines.is_empty() {
        "- none".to_string()
    } else {
        lines
    }
}

fn prompt_threat_rows(document: &Value) -> impl Iterator<Item = String> {
    document
        .get("threats")
        .and_then(Value::as_array)
        .map(|threats| {
            threats
                .iter()
                .take(MAX_PROMPT_THREATS)
                .filter_map(threat_prompt_row)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
        .into_iter()
}

fn threat_prompt_row(threat: &Value) -> Option<String> {
    let stable_id = threat.get("stableId").and_then(Value::as_str)?;
    let title = threat
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("untitled");
    Some(format!("{stable_id} · {title}"))
}

/// Deterministic fold of the closer response: validated answers remove their
/// question and land as a control on the named threat or as a context note;
/// rejected answers leave the question open and record why.
fn fold_answered_questions(
    document: &mut Value,
    response: &Value,
    index: &BTreeSet<String>,
) -> usize {
    let answered = response
        .get("answered")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut warnings = Vec::new();
    let closed = answered
        .iter()
        .filter(|row| fold_answer_row(document, row, index, &mut warnings))
        .count();
    append_closer_warnings(document, warnings);
    closed
}

fn fold_answer_row(
    document: &mut Value,
    row: &Value,
    index: &BTreeSet<String>,
    warnings: &mut Vec<String>,
) -> bool {
    let Some(question) = row.get("question").and_then(Value::as_str).map(str::trim) else {
        return false;
    };
    let Some(answer) = non_empty_str(row.get("answer")) else {
        return false;
    };
    let refs = indexed_refs(row, index);
    if refs.is_empty() {
        warnings.push(format!(
            "question-closer: kept \"{question}\" open — answer cited no indexed evidence"
        ));
        return false;
    }
    if !remove_open_question(document, question) {
        warnings.push(format!(
            "question-closer: answer for unknown question \"{question}\" ignored"
        ));
        return false;
    }
    apply_answer(document, row, question, &answer, &refs);
    true
}

fn non_empty_str(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

fn indexed_refs(row: &Value, index: &BTreeSet<String>) -> Vec<String> {
    row.get("evidenceRefs")
        .and_then(Value::as_array)
        .map(|refs| {
            refs.iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|reference| index.contains(*reference))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn remove_open_question(document: &mut Value, question: &str) -> bool {
    let Some(rows) = document
        .get_mut("openQuestions")
        .and_then(Value::as_array_mut)
    else {
        return false;
    };
    let before = rows.len();
    rows.retain(|row| open_question_text(row).as_deref() != Some(question));
    rows.len() < before
}

fn apply_answer(document: &mut Value, row: &Value, question: &str, answer: &str, refs: &[String]) {
    let fold_into = row.get("foldInto").and_then(Value::as_str).unwrap_or("context");
    if fold_into == "controls" {
        if let Some(threat) = matched_threat_mut(document, row) {
            push_control(threat, question, answer, refs);
            return;
        }
    }
    push_context_note(document, question, answer, refs);
}

fn matched_threat_mut<'a>(document: &'a mut Value, row: &Value) -> Option<&'a mut Value> {
    let target = row.get("threatStableId").and_then(Value::as_str)?.trim();
    document
        .get_mut("threats")?
        .as_array_mut()?
        .iter_mut()
        .find(|threat| {
            ["stableId", "id"].iter().any(|key| {
                threat.get(*key).and_then(Value::as_str) == Some(target)
            })
        })
}

fn push_control(threat: &mut Value, question: &str, answer: &str, refs: &[String]) {
    ensure_array(threat, "existingMitigations");
    if let Some(controls) = threat
        .get_mut("existingMitigations")
        .and_then(Value::as_array_mut)
    {
        controls.push(json!(answer));
    }
    ensure_array(threat, "evidence");
    if let Some(evidence) = threat.get_mut("evidence").and_then(Value::as_array_mut) {
        evidence.push(json!({
            "kind": "question-closed",
            "ref": refs[0],
            "summary": question,
            "addedBy": "refine",
        }));
    }
}

fn push_context_note(document: &mut Value, question: &str, answer: &str, refs: &[String]) {
    ensure_array(document, "contextNotes");
    if let Some(notes) = document.get_mut("contextNotes").and_then(Value::as_array_mut) {
        notes.push(json!({
            "note": answer,
            "question": question,
            "evidenceRefs": refs,
            "addedBy": "refine",
        }));
    }
}

fn ensure_array(value: &mut Value, key: &str) {
    if !value.get(key).is_some_and(Value::is_array) {
        value[key] = json!([]);
    }
}

fn append_closer_warnings(document: &mut Value, warnings: Vec<String>) {
    if warnings.is_empty() {
        return;
    }
    ensure_array(document, "normalizationWarnings");
    if let Some(rows) = document
        .get_mut("normalizationWarnings")
        .and_then(Value::as_array_mut)
    {
        rows.extend(warnings.into_iter().map(Value::String));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document_with_question() -> Value {
        json!({
            "threats": [{
                "stableId": "tm-abc123def456",
                "title": "Unauthenticated ingest",
                "existingMitigations": [],
                "evidence": []
            }],
            "openQuestions": [
                {"question": "Is the ingest endpoint behind mTLS?", "source": "build"},
                "Does the CI pipeline pin action digests?"
            ]
        })
    }

    fn index() -> BTreeSet<String> {
        BTreeSet::from(["src/ingest.rs:42".to_string(), "Dockerfile".to_string()])
    }

    #[test]
    fn grounded_controls_answer_closes_question_and_lands_on_the_threat() {
        let mut document = document_with_question();
        let response = json!({
            "answered": [{
                "question": "Is the ingest endpoint behind mTLS?",
                "answer": "Ingest requires client certificates via the tls acceptor.",
                "evidenceRefs": ["src/ingest.rs:42"],
                "foldInto": "controls",
                "threatStableId": "tm-abc123def456"
            }],
            "unanswered": []
        });
        let closed = fold_answered_questions(&mut document, &response, &index());
        assert_eq!(closed, 1);
        assert_eq!(open_question_texts(&document).len(), 1, "the CI question stays open");
        let threat = &document["threats"][0];
        assert_eq!(
            threat["existingMitigations"][0],
            json!("Ingest requires client certificates via the tls acceptor.")
        );
        assert_eq!(threat["evidence"][0]["addedBy"], json!("refine"));
        assert_eq!(threat["evidence"][0]["ref"], json!("src/ingest.rs:42"));
    }

    #[test]
    fn answer_without_indexed_evidence_keeps_the_question_open_with_a_warning() {
        let mut document = document_with_question();
        let response = json!({
            "answered": [{
                "question": "Is the ingest endpoint behind mTLS?",
                "answer": "Probably yes.",
                "evidenceRefs": ["docs/invented.md:1"],
                "foldInto": "context"
            }],
            "unanswered": []
        });
        let closed = fold_answered_questions(&mut document, &response, &index());
        assert_eq!(closed, 0);
        assert_eq!(open_question_texts(&document).len(), 2);
        assert!(document["normalizationWarnings"][0]
            .as_str()
            .is_some_and(|warning| warning.contains("no indexed evidence")));
    }

    #[test]
    fn context_answer_without_threat_match_becomes_a_tagged_context_note() {
        let mut document = document_with_question();
        let response = json!({
            "answered": [{
                "question": "Does the CI pipeline pin action digests?",
                "answer": "The workflow pins actions by full commit sha.",
                "evidenceRefs": ["Dockerfile"],
                "foldInto": "context"
            }],
            "unanswered": []
        });
        let closed = fold_answered_questions(&mut document, &response, &index());
        assert_eq!(closed, 1);
        let note = &document["contextNotes"][0];
        assert_eq!(note["addedBy"], json!("refine"));
        assert_eq!(note["evidenceRefs"], json!(["Dockerfile"]));
    }

    #[test]
    fn answer_for_an_unknown_question_is_ignored_with_a_warning() {
        let mut document = document_with_question();
        let response = json!({
            "answered": [{
                "question": "A question nobody asked?",
                "answer": "Grounded but irrelevant.",
                "evidenceRefs": ["Dockerfile"],
                "foldInto": "context"
            }],
            "unanswered": []
        });
        let closed = fold_answered_questions(&mut document, &response, &index());
        assert_eq!(closed, 0);
        assert!(document.get("contextNotes").is_none());
        assert!(document["normalizationWarnings"][0]
            .as_str()
            .is_some_and(|warning| warning.contains("unknown question")));
    }
}
