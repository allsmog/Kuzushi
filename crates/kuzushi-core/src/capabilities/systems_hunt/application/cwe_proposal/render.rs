use super::*;
use crate::runtime::{AgentQueryResponse, RuntimeCostReport};

pub(super) fn result(
    prepared: context::Prepared,
    system: String,
    model: String,
    response: AgentQueryResponse,
    maximum: usize,
    canceled: bool,
) -> Result<Value> {
    let cost = response.checked_cost_report()?;
    let parsed = if canceled {
        Err(anyhow::anyhow!(
            "CWE proposal canceled after the request; no further work started"
        ))
    } else {
        response::validate(&response, maximum)
    };
    let mut result = match parsed {
        Ok(cwes) => valid(&prepared, &cwes, cost),
        Err(error) => crate::module_result::failed_output_result(
            "CWE proposal failed",
            format!("{error:#}. No repair request, scan jobs or findings were created."),
            json!({"cwes":[],"parseError":format!("{error:#}")}),
        ),
    };
    result["data"]["inspection"] = prepared.inspection;
    result["data"]["frozenInput"] = serde_json::from_str::<Value>(&prepared.prompt)?;
    result["data"]["systemPrompt"] = json!(system);
    result["data"]["model"] = json!(model);
    result["data"]["costUsd"] = json!(cost.exact_usd());
    result["data"]["observedCostUsd"] = json!(cost.observed_usd());
    result["data"]["costUsdExact"] = json!(cost.is_complete());
    result["data"]["rawAgentOutput"] = json!(response::raw_value(&response).ok());
    result["data"]["rawAgentText"] = json!(context::prefix(&response.text, 64 * 1024));
    result["data"]["rawAgentTextTruncated"] = json!(response.text.len() > 64 * 1024);
    result["data"]["accepted"] = json!(false);
    append_inputs(&mut result, &prepared.prompt, &system)?;
    crate::module_result::apply_runtime_cost_report(&mut result, cost);
    Ok(result)
}

fn append_inputs(result: &mut Value, prompt: &str, system: &str) -> Result<()> {
    let supplied: Value = serde_json::from_str(prompt)?;
    let mut lines = vec!["FROZEN MODEL INPUT".to_string(),
        "Historical supplied text. Reading it does not verify current source freshness or start work.".into()];
    append_frozen_settings(&mut lines, &supplied);
    for source in supplied["sources"]
        .as_array()
        .context("Frozen sources are missing")?
    {
        lines.push(format!(
            "Source: {}\n{}",
            source["path"].as_str().unwrap_or("unavailable"),
            source["text"].as_str().unwrap_or("")
        ));
    }
    for label in ["context", "threatModel"] {
        lines.push(format!(
            "{label}: {}",
            supplied[label].as_str().unwrap_or("explicitly absent")
        ));
    }
    lines.push(format!(
        "Selected threat model reference: {}",
        supplied["selectedThreatModelRef"]
    ));
    lines.push(format!("System instructions:\n{system}"));
    result["output"] = json!(format!(
        "{}\n\n{}",
        result["output"].as_str().unwrap_or(""),
        lines.join("\n")
    ));
    Ok(())
}

fn append_frozen_settings(lines: &mut Vec<String>, supplied: &Value) {
    lines.extend([
        format!(
            "Task supplied: {}",
            supplied["task"].as_str().unwrap_or("unavailable")
        ),
        format!("Maximum classes supplied: {}", supplied["maxClasses"]),
        format!(
            "Scope supplied: {}",
            supplied["scope"].as_str().unwrap_or("unavailable")
        ),
        format!(
            "Complete repository coverage supplied: {}",
            supplied["completeRepositoryCoverage"]
        ),
        format!("Input schema version: {}", supplied["schemaVersion"]),
    ]);
}

fn valid(
    prepared: &context::Prepared,
    cwes: &[DeepSemanticCweSelection],
    cost: RuntimeCostReport,
) -> Value {
    let receipt = &prepared.inspection;
    let partial = receipt["status"] == "partial";
    let summary = format!(
        "CWE proposals: {} {}; {} source context",
        cwes.len(),
        if cwes.len() == 1 { "class" } else { "classes" },
        if partial { "partial" } else { "bounded" }
    );
    let text = render(cwes, &summary, receipt, cost);
    let data = json!({"cwes":cwes});
    if partial {
        return crate::module_result::partial_output_result(
            &summary,
            text,
            vec![json!(
                "Partial source context. Review coverage before selecting further work."
            )],
            data,
        );
    }
    crate::module_result::completed_output_result(summary, text, data)
}

fn render(
    cwes: &[DeepSemanticCweSelection],
    summary: &str,
    receipt: &Value,
    cost: RuntimeCostReport,
) -> String {
    let mut lines = vec![
        summary.into(),
        "Proposals require review. They are not vulnerability verdicts or accepted scan context."
            .into(),
        "No scan jobs or findings were created. No tools, source execution or automatic repair."
            .into(),
    ];
    for cwe in cwes {
        lines.push(format!("{} · {}\n  Why: {}", cwe.id, cwe.name, cwe.reason));
    }
    lines.extend([
        format!("Source: {}, {} inspected bytes. Prompt: {}; {} omitted; {} clipped.", files(&receipt["indexedFiles"]), receipt["inspectedSourceBytes"], files(&receipt["promptSourceFiles"]), receipt["promptOmittedFiles"], receipt["promptTruncatedSourceFiles"]),
        format!("Limits: {}, {} source bytes, {} bytes/file. Truncated source prefixes: {}.", files(&receipt["maxSourceFiles"]), receipt["maxSourceBytes"], receipt["maxFileBytes"], receipt["truncatedSourceFiles"]),
        "Scope: repository-wide planning prefixes. Selected discovery scopes are unsupported.".into(),
        "Coverage: complete repository coverage is not established.".into(),
        format!("Context: {}. Threat model: {}. Inspect the saved frozen inputs for exact supplied text.", receipt["context"]["status"].as_str().unwrap_or("unavailable"), receipt["threatModel"]["status"].as_str().unwrap_or("unavailable")),
        format!("Consumption: one model turn requested; no repair loop. {}. Adapter token/turn support varies; transport retries share the approved call allowance.", crate::run_lifecycle::cost_label(cost)),
        "Approve any scan or further investigation separately. Reading this proposal starts no further work.".into(),
    ]);
    append_systems_source_coverage(&mut lines, receipt);
    lines.join("\n")
}

fn files(value: &Value) -> String {
    format!(
        "{value} {}",
        if value.as_u64() == Some(1) {
            "file"
        } else {
            "files"
        }
    )
}
