use super::*;

impl FindingListFilter {
    pub const MAX_LIMIT: usize = 500;

    pub fn with_limit(limit: usize) -> Self {
        Self {
            limit: limit.min(Self::MAX_LIMIT),
            ..Self::default()
        }
    }

    pub fn from_tool_input(input: &Value) -> Result<Self> {
        let mut filter = Self::default();
        filter.apply_filter_input(input)?;
        Ok(filter)
    }

    fn apply_filter_input(&mut self, input: &Value) -> Result<()> {
        self.apply_filter_expression_input(input)?;
        self.severity
            .extend(parsed_severities(string_values(input, "severity")?)?);
        self.verdict
            .extend(parsed_verdicts(string_values(input, "verdict")?)?);
        self.triage_state
            .extend(parsed_triage_states(string_values(input, "state")?)?);
        self.name =
            merge_optional_field(self.name.take(), normalized_optional_string(input, "name")?);
        self.file_path = merge_optional_field(self.file_path.take(), file_path_input(input)?);
        self.run_id.extend(
            string_values_any(input, &["runId", "run_id", "run"])?
                .into_iter()
                .map(normalize_filter_value),
        );
        self.vuln_source.extend(parsed_sources(string_values_any(
            input,
            &["source", "vulnSource", "vuln_source"],
        )?)?);
        self.limit = parsed_limit(input.get("limit"), self.limit)?;
        Ok(())
    }

    fn apply_filter_expression_input(&mut self, input: &Value) -> Result<()> {
        if let Some(expr) = normalized_optional_string(input, "filter")? {
            self.apply_filter_expression(&expr)?;
        }
        Ok(())
    }

    pub fn from_parts(
        severity: Vec<String>,
        verdict: Vec<String>,
        name: Option<String>,
        file_path: Option<String>,
        limit: usize,
    ) -> Result<Self> {
        Self::from_parts_full(severity, verdict, name, file_path, Vec::new(), limit)
    }

    pub fn from_parts_full(
        severity: Vec<String>,
        verdict: Vec<String>,
        name: Option<String>,
        file_path: Option<String>,
        vuln_source: Vec<String>,
        limit: usize,
    ) -> Result<Self> {
        let severity = severity
            .into_iter()
            .flat_map(split_csv)
            .map(|value| Severity::try_from(value.as_str()))
            .collect::<Result<Vec<_>>>()?;
        let verdict = verdict
            .into_iter()
            .flat_map(split_csv)
            .map(|value| FindingVerdictFilter::from_input(&value))
            .collect::<Result<Vec<_>>>()?;
        let vuln_source = vuln_source
            .into_iter()
            .flat_map(split_csv)
            .map(|value| {
                VulnSource::parse(&value)
                    .ok_or_else(|| anyhow::anyhow!("unknown vuln source {value:?}"))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            severity,
            verdict,
            triage_state: Vec::new(),
            name: normalize_string(name),
            text_terms: Vec::new(),
            file_path: normalize_string(file_path),
            run_id: Vec::new(),
            vuln_source,
            limit: limit.min(Self::MAX_LIMIT),
        })
    }

    pub fn from_filter_expression(expression: &str) -> Result<Self> {
        let mut filter = Self::default();
        filter.apply_filter_expression(expression)?;
        Ok(filter)
    }

    fn apply_filter_expression(&mut self, expression: &str) -> Result<()> {
        for token in expression.split_whitespace() {
            self.apply_filter_token(token)?;
        }
        Ok(())
    }

    fn apply_filter_token(&mut self, token: &str) -> Result<()> {
        if token.trim().is_empty() {
            return Ok(());
        }
        if token.starts_with('-') {
            anyhow::bail!("findings:list filter negation is not supported yet: {token:?}");
        }
        let Some((key, raw_value)) = token.split_once(':') else {
            self.text_terms
                .push(normalize_filter_value(token.to_string()));
            return Ok(());
        };
        let values = split_csv(raw_value.to_string()).collect::<Vec<_>>();
        if values.is_empty() {
            anyhow::bail!("findings:list filter {key:?} requires a value");
        }
        self.apply_keyed_filter(key, values)
    }

    fn apply_keyed_filter(&mut self, key: &str, values: Vec<String>) -> Result<()> {
        match FilterKey::parse(key)? {
            FilterKey::Rank => self.severity.extend(parsed_severities(values)?),
            FilterKey::Verdict => self.verdict.extend(parsed_verdicts(values)?),
            FilterKey::State => self.triage_state.extend(parsed_triage_states(values)?),
            FilterKey::Source => self.vuln_source.extend(parsed_sources(values)?),
            FilterKey::File => {
                self.file_path = merge_optional_contains(self.file_path.take(), values)
            }
            FilterKey::Name => self.name = merge_optional_contains(self.name.take(), values),
            FilterKey::Run => self
                .run_id
                .extend(values.into_iter().map(normalize_filter_value)),
            FilterKey::Limit => self.limit = parse_limit_token(values)?,
        }
        Ok(())
    }

    pub(in crate::findings) fn matches(&self, finding: &Finding) -> bool {
        severity_matches(self, finding)
            && triage_state_filter_matches(self, finding)
            && verdict_matches(self, finding)
            && name_matches(self, finding)
            && text_terms_match(self, finding)
            && source_matches(self, finding)
            && file_path_matches(self, finding)
            && run_id_matches(self, finding)
    }
}

fn triage_state_matches(state: FindingTriageStateFilter, finding: &Finding) -> bool {
    match state {
        FindingTriageStateFilter::Untriaged => finding.triage.is_none(),
        FindingTriageStateFilter::Triaged => finding.triage.is_some(),
    }
}

fn severity_matches(filter: &FindingListFilter, finding: &Finding) -> bool {
    filter.severity.is_empty() || filter.severity.contains(&finding.severity)
}

fn triage_state_filter_matches(filter: &FindingListFilter, finding: &Finding) -> bool {
    filter.triage_state.is_empty()
        || filter
            .triage_state
            .iter()
            .any(|state| triage_state_matches(*state, finding))
}

fn verdict_matches(filter: &FindingListFilter, finding: &Finding) -> bool {
    filter.verdict.is_empty()
        || filter
            .verdict
            .contains(&FindingVerdictFilter::from_finding(finding))
}

fn name_matches(filter: &FindingListFilter, finding: &Finding) -> bool {
    match &filter.name {
        Some(name) => finding
            .title
            .to_ascii_lowercase()
            .contains(&name.to_ascii_lowercase()),
        None => true,
    }
}

fn text_terms_match(filter: &FindingListFilter, finding: &Finding) -> bool {
    filter
        .text_terms
        .iter()
        .all(|term| finding_contains_text(finding, term))
}

fn source_matches(filter: &FindingListFilter, finding: &Finding) -> bool {
    if filter.vuln_source.is_empty() {
        return true;
    }
    let observed = finding
        .vuln_source
        .unwrap_or_else(|| VulnSource::from_tool(&finding.tool));
    filter.vuln_source.contains(&observed)
}

fn file_path_matches(filter: &FindingListFilter, finding: &Finding) -> bool {
    match &filter.file_path {
        Some(file_path) => finding
            .file_path
            .to_ascii_lowercase()
            .contains(&file_path.to_ascii_lowercase()),
        None => true,
    }
}

fn run_id_matches(filter: &FindingListFilter, finding: &Finding) -> bool {
    filter.run_id.is_empty()
        || filter
            .run_id
            .iter()
            .any(|run_id| run_matches(finding, run_id))
}

fn finding_contains_text(finding: &Finding, term: &str) -> bool {
    let term = term.to_ascii_lowercase();
    [
        finding.title.as_str(),
        finding.file_path.as_str(),
        finding.rule_id.as_str(),
        finding.message.as_str(),
    ]
    .into_iter()
    .any(|value| value.to_ascii_lowercase().contains(&term))
}

fn run_matches(finding: &Finding, run_id: &str) -> bool {
    finding
        .scan_id
        .as_deref()
        .map(|scan_id| {
            let scan_id = scan_id.to_ascii_lowercase();
            scan_id == run_id || scan_id.starts_with(run_id)
        })
        .unwrap_or(false)
}

fn normalize_filter_key(key: &str) -> String {
    key.trim()
        .trim_start_matches('-')
        .to_ascii_lowercase()
        .replace(['_', '-'], "")
}

fn string_values_any(input: &Value, keys: &[&str]) -> Result<Vec<String>> {
    let mut values = Vec::new();
    for key in keys {
        values.extend(string_values(input, key)?);
    }
    Ok(values)
}

fn file_path_input(input: &Value) -> Result<Option<String>> {
    Ok(normalized_optional_string(input, "filePath")?
        .or(normalized_optional_string(input, "file_path")?))
}

fn parsed_severities(values: Vec<String>) -> Result<Vec<Severity>> {
    values
        .into_iter()
        .map(|value| Severity::try_from(value.as_str()))
        .collect()
}

fn parsed_verdicts(values: Vec<String>) -> Result<Vec<FindingVerdictFilter>> {
    values
        .into_iter()
        .map(|value| FindingVerdictFilter::from_input(&value))
        .collect()
}

fn parsed_triage_states(values: Vec<String>) -> Result<Vec<FindingTriageStateFilter>> {
    values
        .into_iter()
        .map(|value| FindingTriageStateFilter::from_input(&value))
        .collect()
}

fn parsed_sources(values: Vec<String>) -> Result<Vec<VulnSource>> {
    values
        .into_iter()
        .map(|value| {
            VulnSource::parse(&value)
                .ok_or_else(|| anyhow::anyhow!("unknown vuln source {value:?}"))
        })
        .collect()
}

enum FilterKey {
    Rank,
    Verdict,
    State,
    Source,
    File,
    Name,
    Run,
    Limit,
}

impl FilterKey {
    fn parse(key: &str) -> Result<Self> {
        match normalize_filter_key(key).as_str() {
            "rank" | "severity" => Ok(Self::Rank),
            "verdict" | "conf" | "confirmation" => Ok(Self::Verdict),
            "state" | "triage" => Ok(Self::State),
            "source" | "channel" => Ok(Self::Source),
            "file" | "path" => Ok(Self::File),
            "name" | "title" | "q" => Ok(Self::Name),
            "run" | "runid" | "scan" => Ok(Self::Run),
            "limit" => Ok(Self::Limit),
            "rev" | "revision" | "sha" | "branch" | "dirty" | "owner" | "changed" | "strategy"
            | "strat" | "scope" => unsupported_future_key(key),
            other => anyhow::bail!("unknown findings:list filter key {other:?}"),
        }
    }
}

fn unsupported_future_key<T>(key: &str) -> Result<T> {
    anyhow::bail!(
        "findings:list filter key {key:?} is not supported until provenance indexing is available"
    )
}

fn normalize_filter_value(value: String) -> String {
    value.trim().to_ascii_lowercase()
}

fn merge_optional_contains(current: Option<String>, values: Vec<String>) -> Option<String> {
    let next = values
        .into_iter()
        .map(normalize_filter_value)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    match (current, next.is_empty()) {
        (Some(current), false) => Some(format!("{current} {next}")),
        (Some(current), true) => Some(current),
        (None, false) => Some(next),
        (None, true) => None,
    }
}

fn merge_optional_field(current: Option<String>, next: Option<String>) -> Option<String> {
    match (current, next) {
        (Some(current), Some(next)) => Some(format!("{current} {next}")),
        (Some(current), None) => Some(current),
        (None, Some(next)) => Some(next),
        (None, None) => None,
    }
}

fn parse_limit_token(values: Vec<String>) -> Result<usize> {
    if values.len() != 1 {
        anyhow::bail!("findings:list filter limit expects one value");
    }
    values[0]
        .parse::<usize>()
        .with_context(|| "findings:list filter limit must be a non-negative integer")
        .map(|value| value.min(FindingListFilter::MAX_LIMIT))
}

fn parsed_limit(value: Option<&Value>, current: usize) -> Result<usize> {
    match value {
        Some(value) => parse_limit_value(value),
        None => Ok(current),
    }
}

fn parse_limit_value(value: &Value) -> Result<usize> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .with_context(|| "findings:list limit must be a non-negative integer")
            .map(|value| value.min(FindingListFilter::MAX_LIMIT as u64) as usize),
        Value::String(value) => value
            .parse::<usize>()
            .with_context(|| "findings:list limit must be a non-negative integer")
            .map(|value| value.min(FindingListFilter::MAX_LIMIT)),
        _ => anyhow::bail!("findings:list limit must be a number"),
    }
}
