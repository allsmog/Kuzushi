use super::*;

impl TaintIrisReport {
    pub(crate) fn output(&self) -> String {
        let mut lines = vec![self.summary()];
        append_cwe_selection(&mut lines, &self.cwes);
        append_persisted_run(&mut lines, self.persisted.as_ref());
        append_top_findings(&mut lines, &self.findings);
        lines.join("\n")
    }

    pub(crate) fn to_tool_json(&self) -> Value {
        let mut output = crate::module_result::completed_output_result(
            self.summary(),
            self.output(),
            json!(self),
        );
        output["costUsd"] = json!(self.cost_usd);
        output
    }

    fn summary(&self) -> String {
        format!(
            "taint-iris: {} finding{} under {}",
            self.count,
            plural_suffix(self.count),
            self.target
        )
    }
}

fn append_cwe_selection(lines: &mut Vec<String>, cwes: &[TaintCweSelection]) {
    if cwes.is_empty() {
        lines.push("  CWE classes: none selected".to_string());
        return;
    }
    lines.push(format!("  CWE classes: {}", cwe_ids(cwes).join(", ")));
}

fn cwe_ids(cwes: &[TaintCweSelection]) -> Vec<&str> {
    cwes.iter().map(|cwe| cwe.id.as_str()).collect()
}

fn append_persisted_run(lines: &mut Vec<String>, persisted: Option<&TaintIrisPersistedRun>) {
    if let Some(persisted) = persisted {
        lines.push(format!(
            "  Persisted run: {} ({})",
            persisted.run_id, persisted.findings_db
        ));
    }
}

fn append_top_findings(lines: &mut Vec<String>, findings: &[Finding]) {
    if findings.is_empty() {
        return;
    }
    lines.push(String::new());
    lines.push("Top findings:".to_string());
    lines.extend(findings.iter().take(10).map(finding_line));
    append_remaining_count(lines, findings.len());
}

fn finding_line(finding: &Finding) -> String {
    format!(
        "  - {} - {} - {}:{}",
        finding.severity.as_str(),
        finding.rule_id,
        finding.file_path,
        finding.start_line
    )
}

fn append_remaining_count(lines: &mut Vec<String>, finding_count: usize) {
    if finding_count > 10 {
        lines.push(format!("  ... and {} more", finding_count - 10));
    }
}

fn plural_suffix(count: usize) -> &'static str {
    (count != 1).then_some("s").unwrap_or("")
}

pub(crate) fn run_taint_cwe_select(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let model = optional_nonempty_string(&input, "model")?.or_else(|| ctx.config.model.clone());
    let cwes = run_taint_cwe_select_value(&input, &target, runtime, model.as_deref())?;
    let summary = format!(
        "pipeline:taint-cwe-select selected {} CWE class{}",
        cwes.len(),
        if cwes.len() == 1 { "" } else { "es" }
    );
    let data = json!({
        "target": target.display().to_string(),
        "cwes": cwes,
    });
    Ok(crate::module_result::completed_output_result(
        summary.clone(),
        summary,
        data,
    ))
}
