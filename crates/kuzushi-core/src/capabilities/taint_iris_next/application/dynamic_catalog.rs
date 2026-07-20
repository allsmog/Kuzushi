use super::*;
use serde::Deserialize;
use std::path::PathBuf;

/// Path where a target-specific catalog is persisted, if generated.
pub(crate) fn taint_iris_next_target_catalog_path(repo_root: &Path) -> PathBuf {
    taint_iris_next_target_catalog_artifact_path(repo_root)
}

/// Try to load a target-specific catalog from disk. Returns `None` when
/// no catalog has been generated yet — callers fall back to the static
/// `TAINT_IRIS_NEXT_CATALOG`.
pub(crate) fn load_taint_iris_next_target_catalog(
    repo_root: &Path,
) -> Option<Vec<TaintIrisNextRankedCatalogEntry>> {
    let path = taint_iris_next_target_catalog_path(repo_root);
    let raw = crate::bounded_file::read_utf8_text_within(repo_root, &path, 8 * 1024 * 1024).ok()?;
    parse_target_catalog_payload(&raw).ok()
}

/// Result of running the `taint-iris-next:catalog` tool. Persists the
/// catalog and surfaces a tool-shaped JSON for the caller.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintIrisNextCatalogReport {
    pub(crate) target: String,
    pub(crate) status: String,
    pub(crate) catalog_path: String,
    pub(crate) entries: Vec<TaintIrisNextRankedCatalogEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) raw_agent_output: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) parse_error: Option<String>,
    #[serde(skip)]
    pub(crate) cost_usd: f64,
    #[serde(skip)]
    pub(crate) cost_usd_exact: bool,
    #[serde(skip)]
    pub(crate) ok: bool,
}

impl TaintIrisNextCatalogReport {
    pub(crate) fn to_tool_json(&self) -> Value {
        let mut output = json!({
            "ok": self.ok,
            "output": render_catalog_summary(self),
            "data": serde_json::to_value(self).unwrap_or(Value::Null),
        });
        let observed = RuntimeCost::from_usd(self.cost_usd, "taint catalog cost")
            .expect("catalog runtime response cost was checked");
        let cost = if self.cost_usd_exact {
            RuntimeCostReport::known(observed)
        } else {
            RuntimeCostReport::incomplete(observed)
        };
        crate::module_result::apply_runtime_cost_report(&mut output, cost);
        output
    }
}

fn render_catalog_summary(report: &TaintIrisNextCatalogReport) -> String {
    let mut lines = vec![
        format!("taint-iris-next:catalog — {}", report.status),
        format!("target: {}", report.target),
        format!("path:   {}", report.catalog_path),
        format!("entries: {}", report.entries.len()),
        String::new(),
    ];
    for entry in report.entries.iter().take(15) {
        lines.push(format!(
            "- {}: {} [{}] languages={} score={}",
            entry.cwe,
            entry.name,
            entry.taint_class,
            entry.languages.join(","),
            entry.score
        ));
        if !entry.source_signals.is_empty() {
            lines.push(format!(
                "    sources: {}",
                entry
                    .source_signals
                    .iter()
                    .take(6)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
        if !entry.sink_signals.is_empty() {
            lines.push(format!(
                "    sinks:   {}",
                entry
                    .sink_signals
                    .iter()
                    .take(6)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
    }
    if report.entries.len() > 15 {
        lines.push(format!("...and {} more", report.entries.len() - 15));
    }
    lines.join("\n")
}

/// Generate a target-specific catalog by asking the agent to produce CWE
/// entries tailored to the codebase. Persists the result and returns
/// the report.
pub(crate) fn run_taint_iris_next_catalog_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<TaintIrisNextCatalogReport> {
    let target = resolve_tool_target(input, ctx)?;
    ensure_catalog_target_dir(&target)?;
    let runtime = require_taint_iris_next_runtime(runtime)?;
    let model = require_taint_iris_next_model(input, ctx)?;

    let (languages, prompt) = catalog_prompt_context(&target)?;
    let system_prompt = optional_taint_next_string(input, &["TAINT_IRIS_NEXT_CATALOG_PROMPT"])?
        .unwrap_or_else(|| TAINT_IRIS_NEXT_CATALOG_SYSTEM_PROMPT.to_string());

    let response = query_catalog_agent(runtime, model, &target, system_prompt, prompt)?;
    let cost = response.checked_cost_report()?;
    let raw_value = catalog_raw_value(&response);
    let (entries, parse_error) = parse_catalog_entries(raw_value.as_ref(), &languages);

    let catalog_path = taint_iris_next_target_catalog_path(&target);
    let status = persist_catalog_status(&target, &entries);
    let ok = status == "generated";

    Ok(TaintIrisNextCatalogReport {
        target: target.display().to_string(),
        status,
        catalog_path: catalog_path.display().to_string(),
        entries,
        raw_agent_output: raw_value,
        parse_error,
        cost_usd: cost.observed_usd(),
        cost_usd_exact: cost.is_complete(),
        ok,
    })
}

/// Reuse the hunt's plan inputs so catalog generation sees the same language,
/// context, and threat-model view as the eventual analysis pass.
fn catalog_prompt_context(target: &Path) -> Result<(Vec<String>, String)> {
    let context = load_taint_iris_next_context(target);
    let threat_model = load_taint_iris_next_threat_model(target);
    let languages = catalog_languages(target, context.value.as_ref())?;
    let keywords = taint_iris_next_context_keywords(context.value.as_ref(), target)?;
    let prompt = build_catalog_prompt(
        target,
        &languages,
        &keywords,
        context.value.as_ref(),
        threat_model.value.as_ref(),
    );
    Ok((languages, prompt))
}

fn query_catalog_agent(
    runtime: &dyn AgentRuntime,
    model: String,
    target: &Path,
    system_prompt: String,
    prompt: String,
) -> Result<AgentQueryResponse> {
    crate::runtime::query_blocking_checked(runtime, AgentQueryRequest::new(
        model,
        target.to_path_buf(),
        system_prompt,
        prompt,
    ))
}

fn ensure_catalog_target_dir(target: &Path) -> Result<()> {
    if target.is_dir() {
        return Ok(());
    }
    anyhow::bail!(
        "taint-iris-next:catalog target is not a directory: {}",
        target.display()
    )
}

fn catalog_languages(target: &Path, context: Option<&Value>) -> Result<Vec<String>> {
    let mut languages = taint_iris_next_context_languages(context);
    languages.extend(detect_taint_iris_next_languages(target)?);
    Ok(languages
        .into_iter()
        .map(|language| normalize_taint_next_language(&language))
        .filter(|language| !language.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn catalog_raw_value(response: &AgentQueryResponse) -> Option<Value> {
    match response.structured.clone() {
        Some(value @ Value::Object(_)) => Some(value),
        Some(value @ Value::Array(_)) => Some(value),
        _ => parse_json_object_from_agent_text(&response.text)
            .ok()
            .or_else(|| serde_json::from_str::<Value>(response.text.trim()).ok()),
    }
}

fn parse_catalog_entries(
    raw_value: Option<&Value>,
    languages: &[String],
) -> (Vec<TaintIrisNextRankedCatalogEntry>, Option<String>) {
    match raw_value
        .and_then(extract_catalog_array)
        .map(|array| normalize_catalog_entries(&array, languages))
    {
        Some(Ok(entries)) if !entries.is_empty() => (entries, None),
        Some(Ok(_)) => (
            Vec::new(),
            Some("agent returned an empty catalog array".to_string()),
        ),
        Some(Err(error)) => (Vec::new(), Some(format!("normalize: {error}"))),
        None => (
            Vec::new(),
            Some("agent did not return a recognisable JSON catalog".to_string()),
        ),
    }
}

fn persist_catalog_status(target: &Path, entries: &[TaintIrisNextRankedCatalogEntry]) -> String {
    if entries.is_empty() {
        return "agent-output-invalid".to_string();
    }
    persist_target_catalog(target, entries)
        .map(|_| "generated".to_string())
        .unwrap_or_else(|error| format!("persist-failed: {error}"))
}

/// System prompt that frames the catalog generation task.
pub(crate) const TAINT_IRIS_NEXT_CATALOG_SYSTEM_PROMPT: &str =
    "You are Kuzushi's Taint IRIS Next catalog architect. \
Given a target codebase profile, produce a JSON catalog of CWE-themed \
taint-analysis entries that are *specific to this codebase's domain, \
languages, and frameworks*. Each entry must be defensible: source \
signals must be observable identifiers/calls in this codebase, sink \
signals must be observable risky operations in this codebase, and \
sanitizer signals must reflect this codebase's actual mitigations. \
Reply only with strict JSON of the shape: \
{\"catalog\":[{\"cwe\":\"CWE-89\",\"name\":\"SQL Injection\",\
\"taintClass\":\"sql-injection\",\"languages\":[\"c\",\"any\"],\
\"sourceSignals\":[\"...\"],\"sinkSignals\":[\"...\"],\
\"sanitizerSignals\":[\"...\"],\"structuralQueries\":[\"...\"],\
\"regexMarkers\":[{\"pattern\":\"...\",\"kind\":\"source|sink|entrypoint\",\
\"languages\":[\"c\"],\"marker\":\"short-tag\"}],\
\"score\":75,\"reasons\":[\"why this CWE matters here\"]}]}. \
Aim for 6-12 entries. Sources/sinks should be substring patterns that \
ripgrep can match against call expressions in this codebase (e.g. \
`PG_GETARG_TEXT_PP`, `palloc`, `appendStringInfo`, `BlessTupleDesc`), \
not generic English words. Score 0-100 reflects how relevant the CWE \
is for this codebase. Use \"any\" in languages when the CWE applies \
broadly, or restrict to languages actually present. \
\n\n\
**regexMarkers** are per-CWE regex patterns that match call-shape \
primitives specific to THIS codebase, *not* framework-canonical names \
already covered by kuzushi's static discovery (`dlopen(`, `system(`, \
`PG_FUNCTION_INFO_V1`, `@app.route`, Express `app.get(...)`, etc. — \
DO NOT repeat those). Emit them when the codebase has a consistent \
*internal* naming convention for parser reads, allocator wrappers, \
or wire-protocol decoders. Examples of when to emit: pgcrypto's \
`pullf_<name>(...)`, `mbuf_<name>(...)`, and `<crypto>_mpi_read(...)` \
family of byte-readers (CWE-120 sources); libxml2's `xmlParse*(...)` \
family; ImageMagick's `Read<Format>Image(...)` family. Skip when the \
sources are already generic library symbols (`fread`, `pq_getmsgbytes`, \
`recv`, `read`) — the static discovery table covers those. Each \
marker carries: \
{`pattern` (PCRE/RE2 with a capture group around the function name \
when possible), `kind` (\"source\"/\"sink\"/\"entrypoint\"), \
`languages` (subset of the entry's languages), `marker` (short tag \
the agent sees on each linked story so it knows WHICH discoverer \
surfaced this name)}. Aim for 0-4 markers per entry; absence is fine.";

fn build_catalog_prompt(
    target: &Path,
    languages: &[String],
    context_keywords: &str,
    context: Option<&Value>,
    threat_model: Option<&Value>,
) -> String {
    let context_excerpt = context
        .and_then(|value| serde_json::to_string_pretty(value).ok())
        .map(|text| {
            // The context snapshot can be large; truncate so the catalog
            // prompt doesn't blow past the model's context budget.
            if text.len() > 12_000 {
                format!("{}\n... (truncated; {} bytes)", &text[..12_000], text.len())
            } else {
                text
            }
        })
        .unwrap_or_else(|| "<no context snapshot>".to_string());

    let threat_excerpt = threat_model
        .and_then(|value| serde_json::to_string_pretty(value).ok())
        .map(|text| {
            if text.len() > 4_000 {
                format!("{}\n... (truncated)", &text[..4_000])
            } else {
                text
            }
        })
        .unwrap_or_else(|| "<no threat model>".to_string());

    let lang_list = if languages.is_empty() {
        "<unknown>".to_string()
    } else {
        languages.join(", ")
    };

    let keyword_excerpt = if context_keywords.len() > 4_000 {
        format!("{}\n... (truncated)", &context_keywords[..4_000])
    } else {
        context_keywords.to_string()
    };

    [
        "## Target".to_string(),
        format!("path: {}", target.display()),
        format!("languages: {lang_list}"),
        String::new(),
        "## Context Snapshot".to_string(),
        context_excerpt,
        String::new(),
        "## Threat Model".to_string(),
        threat_excerpt,
        String::new(),
        "## Manifest / Configuration Keywords".to_string(),
        keyword_excerpt,
        String::new(),
        "## Regex Marker Examples".to_string(),
        // Concrete reference shapes the LLM can mirror per-target.
        // These are *examples* — the actual codebase may use entirely
        // different naming. The point is to demonstrate the regex shape
        // (named-capture or first capture group around the function
        // name, anchored on the open paren) and the right granularity
        // (parser-read families, allocator wrappers, wire-protocol
        // decoders — NOT generic library symbols).
        "Worked example: a CWE-120 entry on a codebase with a `pullf_*` \
parser family and an `<crypto>_mpi_read` MPI reader family might emit \
these regexMarkers (DO NOT copy verbatim — derive the patterns from \
patterns actually present in this target's source tree):\n\
```json\n\
[\n\
  {\"pattern\": \"\\\\b(pullf_[a-z_]+)\\\\s*\\\\(\", \"kind\": \"source\", \"languages\": [\"c\"], \"marker\": \"buffer.parser-read\"},\n\
  {\"pattern\": \"\\\\b([a-z_]+_mpi_(?:read|alloc))\\\\s*\\\\(\", \"kind\": \"source\", \"languages\": [\"c\"], \"marker\": \"crypto.mpi-read\"}\n\
]\n\
```\n\
Other archetypes worth inspecting: libxml2 `xmlParse*`, ImageMagick \
`Read<Format>Image`, OpenSSL `BIO_read`, lwIP `pbuf_*`, kernel \
`skb_pull` / `copy_from_user`."
            .to_string(),
        String::new(),
        "## Output Contract".to_string(),
        "Return strict JSON: { \"catalog\": [...] }. Do not include \
markdown fences, prose, or trailing commentary. Each catalog entry \
must list source/sink/sanitizer signals that are concretely useful \
substrings against THIS codebase's call expressions — generic English \
words like `count`, `length`, `update` are too noisy. Prefer named \
APIs, function-call substrings, library symbols, or framework-specific \
patterns visible in the context above. Emit `regexMarkers` only when \
the codebase has a codebase-internal naming convention not covered by \
generic library names."
            .to_string(),
    ]
    .join("\n")
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CatalogEntryPayload {
    cwe: String,
    #[serde(default)]
    name: String,
    #[serde(default, alias = "taint_class")]
    taint_class: String,
    #[serde(default)]
    languages: Vec<String>,
    #[serde(default, alias = "source_signals")]
    source_signals: Vec<String>,
    #[serde(default, alias = "sink_signals")]
    sink_signals: Vec<String>,
    #[serde(default, alias = "sanitizer_signals")]
    sanitizer_signals: Vec<String>,
    #[serde(default, alias = "structural_queries")]
    structural_queries: Vec<String>,
    /// Optional codebase-shape regex markers. Absent from legacy
    /// catalogs (pre-C2); present once a fresh `:catalog` runs against
    /// the new prompt that elicits them. See
    /// `TaintIrisNextRegexMarker` for the mirror struct on the ranked
    /// entry; both share the wire shape.
    #[serde(default, alias = "regex_markers")]
    regex_markers: Vec<RegexMarkerPayload>,
    #[serde(default)]
    score: i32,
    #[serde(default)]
    reasons: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegexMarkerPayload {
    pattern: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    languages: Vec<String>,
    #[serde(default)]
    marker: String,
}

fn extract_catalog_array(value: &Value) -> Option<Vec<Value>> {
    if let Some(array) = value.get("catalog").and_then(Value::as_array) {
        return Some(array.clone());
    }
    if let Some(array) = value.as_array() {
        return Some(array.clone());
    }
    None
}

fn normalize_catalog_entries(
    array: &[Value],
    fallback_languages: &[String],
) -> Result<Vec<TaintIrisNextRankedCatalogEntry>> {
    let mut out = Vec::new();
    for raw in array {
        let payload: CatalogEntryPayload = serde_json::from_value(raw.clone())?;
        let cwe_normalized = normalize_taint_next_cwe(&payload.cwe);
        if !cwe_normalized.starts_with("CWE-") {
            continue;
        }
        let name = if payload.name.trim().is_empty() {
            cwe_normalized.clone()
        } else {
            payload.name.trim().to_string()
        };
        let taint_class = if payload.taint_class.trim().is_empty() {
            "agent-defined".to_string()
        } else {
            payload.taint_class.trim().to_lowercase()
        };
        let languages = if payload.languages.is_empty() {
            fallback_languages.to_vec()
        } else {
            payload
                .languages
                .iter()
                .map(|language| normalize_taint_next_language(language))
                .filter(|language| !language.is_empty())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        };
        out.push(TaintIrisNextRankedCatalogEntry {
            cwe: cwe_normalized,
            name,
            taint_class,
            languages,
            source_signals: dedup_nonempty(payload.source_signals),
            sink_signals: dedup_nonempty(payload.sink_signals),
            sanitizer_signals: dedup_nonempty(payload.sanitizer_signals),
            structural_queries: dedup_nonempty(payload.structural_queries),
            regex_markers: normalize_regex_markers(payload.regex_markers),
            score: payload.score.clamp(0, 1000),
            reasons: dedup_nonempty(payload.reasons),
        });
    }
    Ok(out)
}

/// Validate and normalize regex markers emitted by the catalog
/// agent. Drops markers whose pattern doesn't compile, whose `kind`
/// isn't one of `source`/`sink`/`entrypoint`, or whose `pattern` is
/// empty after trimming. Silent drop is the right policy: an LLM that
/// emits a malformed regex shouldn't fail the whole catalog
/// generation — the remaining markers stay usable.
fn normalize_regex_markers(markers: Vec<RegexMarkerPayload>) -> Vec<TaintIrisNextRegexMarker> {
    let valid_kinds: &[&str] = &["source", "sink", "entrypoint"];
    markers
        .into_iter()
        .filter_map(|marker| {
            let pattern = marker.pattern.trim().to_string();
            if pattern.is_empty() {
                return None;
            }
            if regex::Regex::new(&pattern).is_err() {
                return None;
            }
            let kind = marker.kind.trim().to_lowercase();
            if !valid_kinds.contains(&kind.as_str()) {
                return None;
            }
            let languages: Vec<String> = marker
                .languages
                .into_iter()
                .map(|language| normalize_taint_next_language(&language))
                .filter(|language| !language.is_empty())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let marker_tag = marker.marker.trim().to_string();
            Some(TaintIrisNextRegexMarker {
                pattern,
                kind,
                languages,
                marker: marker_tag,
            })
        })
        .collect()
}

fn dedup_nonempty(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.clone()) {
            out.push(trimmed);
        }
    }
    out
}

fn parse_target_catalog_payload(raw: &str) -> Result<Vec<TaintIrisNextRankedCatalogEntry>> {
    // Accept either {"catalog":[...]} for round-tripping the agent shape
    // or a bare [...] array for hand-edited files.
    let value: Value = serde_json::from_str(raw).context("invalid JSON in target catalog")?;
    let array = extract_catalog_array(&value)
        .ok_or_else(|| anyhow::anyhow!("target catalog has no `catalog` array or root array"))?;
    let entries = normalize_catalog_entries(&array, &[])?;
    if entries.is_empty() {
        anyhow::bail!("target catalog parsed but contained no usable entries");
    }
    Ok(entries)
}

pub(in crate::capabilities::taint_iris_next) fn persist_target_catalog(
    target: &Path,
    entries: &[TaintIrisNextRankedCatalogEntry],
) -> Result<PathBuf> {
    let payload = serde_json::json!({ "catalog": entries });
    let pretty = serde_json::to_string_pretty(&payload)
        .context("could not serialize target catalog to JSON")?;
    let intended_path = taint_iris_next_target_catalog_path(target);
    let relative = intended_path
        .strip_prefix(target)
        .context("could not resolve target catalog below target")?;
    crate::workspace::write_workspace_state_file(target, relative, pretty.as_bytes())
        .with_context(|| format!("could not write {}", intended_path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::tempdir;

    struct CapturingCatalogRuntime {
        requests: Mutex<Vec<AgentQueryRequest>>,
    }

    impl CapturingCatalogRuntime {
        fn new() -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl AgentRuntime for CapturingCatalogRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            self.requests.lock().unwrap().push(request);
            Ok(AgentQueryResponse::default())
        }

        fn triage_finding_blocking(
            &self,
            _request: crate::runtime::TriageRequest,
        ) -> Result<crate::findings::TriageOutcome> {
            anyhow::bail!("not used by catalog prompt tests")
        }
    }

    #[test]
    fn catalog_query_uses_declared_prompt_override() {
        let runtime = CapturingCatalogRuntime::new();

        query_catalog_agent(
            &runtime,
            "openai:test".to_string(),
            std::path::Path::new("/tmp/catalog-target"),
            "custom catalog system".to_string(),
            "catalog input".to_string(),
        )
        .unwrap();

        let requests = runtime.requests.lock().unwrap();
        assert_eq!(requests[0].system_prompt, "custom catalog system");
    }

    #[test]
    fn extract_catalog_array_accepts_object_or_array() {
        let object = json!({"catalog": [{"cwe": "CWE-89"}]});
        assert!(extract_catalog_array(&object).is_some_and(|a| a.len() == 1));
        let array = json!([{"cwe": "CWE-89"}]);
        assert!(extract_catalog_array(&array).is_some_and(|a| a.len() == 1));
        let neither = json!({"foo": 1});
        assert!(extract_catalog_array(&neither).is_none());
    }

    #[test]
    fn normalize_catalog_entries_drops_invalid_and_clamps_score() {
        let array = json!([
            {
                "cwe": "cwe-89",
                "name": "  SQL Injection  ",
                "taintClass": "  SQL-Injection  ",
                "languages": ["c", "C"],
                "sourceSignals": ["PG_GETARG_TEXT_PP", "  ", "PG_GETARG_TEXT_PP"],
                "sinkSignals": ["palloc"],
                "sanitizerSignals": [],
                "structuralQueries": [],
                "score": 9999,
                "reasons": ["foo"]
            },
            { "cwe": "not-a-cwe" },
            { "cwe": "CWE-22", "name": "Path Traversal" }
        ]);
        let array = array.as_array().unwrap();
        let entries = normalize_catalog_entries(array, &["c".to_string()]).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].cwe, "CWE-89");
        assert_eq!(entries[0].name, "SQL Injection");
        assert_eq!(entries[0].taint_class, "sql-injection");
        assert_eq!(entries[0].languages, vec!["c".to_string()]);
        assert_eq!(entries[0].source_signals, vec!["PG_GETARG_TEXT_PP"]);
        assert_eq!(entries[0].score, 1000);
    }

    #[test]
    fn parse_target_catalog_payload_round_trips_what_we_persist() {
        let entries = vec![TaintIrisNextRankedCatalogEntry {
            cwe: "CWE-89".to_string(),
            name: "SQL Injection".to_string(),
            taint_class: "sql-injection".to_string(),
            languages: vec!["c".to_string()],
            source_signals: vec!["PG_GETARG_TEXT_PP".to_string()],
            sink_signals: vec!["palloc".to_string()],
            sanitizer_signals: vec![],
            structural_queries: vec![],
            regex_markers: vec![],
            score: 80,
            reasons: vec!["postgres backend".to_string()],
        }];
        let payload = serde_json::json!({ "catalog": entries });
        let raw = serde_json::to_string(&payload).unwrap();
        let parsed = parse_target_catalog_payload(&raw).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].cwe, "CWE-89");
        assert_eq!(parsed[0].score, 80);
    }

    #[test]
    fn persist_then_load_round_trip() {
        let temp = tempdir().unwrap();
        let target = temp.path();
        std::fs::create_dir_all(target.join(".kuzushi")).unwrap();
        let entries = vec![TaintIrisNextRankedCatalogEntry {
            cwe: "CWE-22".to_string(),
            name: "Path Traversal".to_string(),
            taint_class: "path-traversal".to_string(),
            languages: vec!["any".to_string()],
            source_signals: vec!["filename".to_string()],
            sink_signals: vec!["fopen".to_string()],
            sanitizer_signals: vec![],
            structural_queries: vec![],
            regex_markers: vec![],
            score: 50,
            reasons: vec![],
        }];
        persist_target_catalog(target, &entries).unwrap();
        let loaded = load_taint_iris_next_target_catalog(target).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].cwe, "CWE-22");
    }

    #[cfg(unix)]
    #[test]
    fn persist_target_catalog_rejects_symlinked_leaf() {
        use std::os::unix::fs::symlink;

        let workspace = tempdir().unwrap();
        let outside = tempdir().unwrap();
        std::fs::create_dir_all(workspace.path().join(".kuzushi")).unwrap();
        let outside_catalog = outside.path().join("catalog.json");
        std::fs::write(&outside_catalog, "outside-sentinel").unwrap();
        symlink(
            &outside_catalog,
            taint_iris_next_target_catalog_path(workspace.path()),
        )
        .unwrap();

        let entries = vec![TaintIrisNextRankedCatalogEntry {
            cwe: "CWE-22".to_string(),
            name: "Path Traversal".to_string(),
            taint_class: "path-traversal".to_string(),
            languages: vec!["any".to_string()],
            source_signals: vec![],
            sink_signals: vec![],
            sanitizer_signals: vec![],
            structural_queries: vec![],
            regex_markers: vec![],
            score: 50,
            reasons: vec![],
        }];

        let error = persist_target_catalog(workspace.path(), &entries).unwrap_err();
        assert!(format!("{error:#}").contains("symlink"));
        assert_eq!(
            std::fs::read_to_string(outside_catalog).unwrap(),
            "outside-sentinel"
        );
    }

    #[test]
    fn normalize_catalog_entries_parses_and_filters_regex_markers() {
        // Three markers: one valid, one with malformed regex, one with
        // invalid `kind`. Only the valid one should survive
        // normalization.
        let array = json!([
            {
                "cwe": "CWE-120",
                "name": "Buffer Overflow",
                "taintClass": "buffer-overflow",
                "languages": ["c"],
                "sourceSignals": [],
                "sinkSignals": ["memcpy("],
                "regexMarkers": [
                    {
                        "pattern": "\\bpullf_[a-z_]+\\(",
                        "kind": "source",
                        "languages": ["c"],
                        "marker": "buffer.parser-read"
                    },
                    {
                        "pattern": "((",
                        "kind": "source",
                        "languages": ["c"],
                        "marker": "broken"
                    },
                    {
                        "pattern": "\\bwhatever\\(",
                        "kind": "unsupported-kind-value",
                        "languages": ["c"],
                        "marker": "rejected"
                    }
                ]
            }
        ]);
        let array = array.as_array().unwrap();
        let entries = normalize_catalog_entries(array, &["c".to_string()]).unwrap();
        assert_eq!(entries.len(), 1);
        let markers = &entries[0].regex_markers;
        assert_eq!(
            markers.len(),
            1,
            "only the valid marker should survive; got {markers:?}"
        );
        assert_eq!(markers[0].pattern, "\\bpullf_[a-z_]+\\(");
        assert_eq!(markers[0].kind, "source");
        assert_eq!(markers[0].marker, "buffer.parser-read");
        assert_eq!(markers[0].languages, vec!["c".to_string()]);
    }

    #[test]
    fn catalog_system_prompt_mentions_regex_markers_field() {
        // C3: the catalog system prompt must teach the LLM about
        // regexMarkers, otherwise the field stays empty in practice and
        // C4 has nothing to lift into the discovery sweep.
        assert!(
            TAINT_IRIS_NEXT_CATALOG_SYSTEM_PROMPT.contains("regexMarkers"),
            "system prompt must elicit regexMarkers"
        );
        // Sanity: the framing should also caution against repeating
        // framework-canonical names already in the static MARKERS table.
        assert!(
            TAINT_IRIS_NEXT_CATALOG_SYSTEM_PROMPT.contains("DO NOT repeat"),
            "system prompt must warn against framework-canonical duplicates"
        );
    }

    #[test]
    fn build_catalog_prompt_includes_regex_marker_examples_section() {
        // The user prompt should show worked examples so the LLM has a
        // concrete shape to mirror. Without this, the regexMarkers
        // field stays empty on most runs.
        let prompt = build_catalog_prompt(
            std::path::Path::new("/tmp/x"),
            &["c".to_string()],
            "",
            None,
            None,
        );
        assert!(
            prompt.contains("Regex Marker Examples"),
            "user prompt must include worked-example section"
        );
        assert!(
            prompt.contains("pullf_"),
            "user prompt must include the pullf_* shape as a reference"
        );
    }

    #[test]
    fn legacy_catalog_without_regex_markers_field_parses_cleanly() {
        // The on-disk catalog format predating C2 has no `regexMarkers`
        // key. Default to empty Vec without erroring.
        let array = json!([{
            "cwe": "CWE-89",
            "name": "SQL Injection",
            "taintClass": "sql-injection",
            "languages": ["c"],
            "sourceSignals": ["PG_GETARG_TEXT_PP"],
            "sinkSignals": ["palloc"]
        }]);
        let array = array.as_array().unwrap();
        let entries = normalize_catalog_entries(array, &["c".to_string()]).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].regex_markers.is_empty());
    }
}
