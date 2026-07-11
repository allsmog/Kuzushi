use super::*;

pub(crate) fn normalize_codeql_result_to_finding(
    result: &CodeqlSarifResult,
    rules_by_id: &HashMap<String, CodeqlSarifRule>,
) -> Option<Finding> {
    let rule_id = codeql_result_rule_id(result);
    let rule = rules_by_id.get(&rule_id);
    let (file_path, start_line) = extract_codeql_location(result)?;
    let message = codeql_result_message(result, rule, &rule_id);
    let severity = codeql_result_severity(result, rule);

    Some(
        Finding::new_tool(
            "codeql", rule_id, file_path, start_line, None, severity, message,
        )
        .with_static_proof_state(StaticProofState::SignalOnly),
    )
}

fn codeql_result_rule_id(result: &CodeqlSarifResult) -> String {
    result
        .rule_id
        .as_deref()
        .and_then(non_empty_string)
        .unwrap_or("codeql.unknown")
        .to_string()
}

fn codeql_result_message(
    result: &CodeqlSarifResult,
    rule: Option<&CodeqlSarifRule>,
    rule_id: &str,
) -> String {
    let message = primary_codeql_message(result)
        .or_else(|| rule.and_then(rule_short_description))
        .unwrap_or(rule_id)
        .to_string();
    append_codeql_flow_evidence(message, result)
}

fn primary_codeql_message(result: &CodeqlSarifResult) -> Option<&str> {
    result
        .message
        .as_ref()
        .and_then(|message| message.text.as_deref().and_then(non_empty_string))
}

fn rule_short_description(rule: &CodeqlSarifRule) -> Option<&str> {
    rule.short_description
        .as_ref()
        .and_then(|description| description.text.as_deref())
        .and_then(non_empty_string)
}

fn append_codeql_flow_evidence(message: String, result: &CodeqlSarifResult) -> String {
    match render_codeql_flow_evidence(result) {
        Some(evidence) => format!("{message}\n\n{evidence}"),
        None => message,
    }
}

fn codeql_result_severity(result: &CodeqlSarifResult, rule: Option<&CodeqlSarifRule>) -> Severity {
    map_codeql_severity(rule_problem_severity(rule), result.level.as_deref())
}

fn rule_problem_severity(rule: Option<&CodeqlSarifRule>) -> Option<&str> {
    rule.and_then(|rule| rule.properties.as_ref())
        .and_then(|properties| properties.problem.as_ref())
        .and_then(|problem| problem.severity.as_deref())
}

#[derive(Debug, Deserialize)]
pub(crate) struct CodeqlSarifOutput {
    #[serde(default)]
    pub(crate) runs: Vec<CodeqlSarifRun>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CodeqlSarifRun {
    #[serde(default)]
    pub(crate) tool: Option<CodeqlSarifTool>,
    #[serde(default)]
    pub(crate) results: Vec<CodeqlSarifResult>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CodeqlSarifTool {
    #[serde(default)]
    pub(crate) driver: Option<CodeqlSarifDriver>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CodeqlSarifDriver {
    #[serde(default)]
    pub(crate) rules: Vec<CodeqlSarifRule>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct CodeqlSarifRule {
    #[serde(default)]
    pub(crate) id: Option<String>,
    #[serde(default, rename = "shortDescription")]
    pub(crate) short_description: Option<CodeqlSarifMessage>,
    #[serde(default)]
    pub(crate) properties: Option<CodeqlRuleProperties>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct CodeqlRuleProperties {
    #[serde(default)]
    pub(crate) problem: Option<CodeqlProblemProperties>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct CodeqlProblemProperties {
    #[serde(default)]
    pub(crate) severity: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CodeqlSarifResult {
    #[serde(default, rename = "ruleId")]
    pub(crate) rule_id: Option<String>,
    #[serde(default)]
    pub(crate) level: Option<String>,
    #[serde(default)]
    pub(crate) message: Option<CodeqlSarifMessage>,
    #[serde(default)]
    pub(crate) locations: Vec<CodeqlSarifLocation>,
    #[serde(default, rename = "codeFlows")]
    pub(crate) code_flows: Vec<CodeqlCodeFlow>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct CodeqlSarifMessage {
    #[serde(default)]
    pub(crate) text: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CodeqlSarifLocation {
    #[serde(default, rename = "physicalLocation")]
    pub(crate) physical_location: Option<CodeqlPhysicalLocation>,
}
