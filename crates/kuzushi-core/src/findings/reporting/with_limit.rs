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

        filter.severity = string_values(input, "severity")?
            .into_iter()
            .map(|value| Severity::try_from(value.as_str()))
            .collect::<Result<Vec<_>>>()?;
        filter.verdict = string_values(input, "verdict")?
            .into_iter()
            .map(|value| FindingVerdictFilter::from_input(&value))
            .collect::<Result<Vec<_>>>()?;
        filter.name = normalized_optional_string(input, "name")?;
        filter.file_path = normalized_optional_string(input, "filePath")?
            .or(normalized_optional_string(input, "file_path")?);
        filter.limit = parsed_limit(input.get("limit"), filter.limit)?;

        Ok(filter)
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
            name: normalize_string(name),
            file_path: normalize_string(file_path),
            vuln_source,
            limit: limit.min(Self::MAX_LIMIT),
        })
    }

    pub(in crate::findings) fn matches(&self, finding: &Finding) -> bool {
        if !self.severity.is_empty() && !self.severity.contains(&finding.severity) {
            return false;
        }

        if !self.verdict.is_empty()
            && !self
                .verdict
                .contains(&FindingVerdictFilter::from_finding(finding))
        {
            return false;
        }

        if let Some(name) = &self.name {
            let title = finding.title.to_ascii_lowercase();
            if !title.contains(name) {
                return false;
            }
        }

        if !self.vuln_source.is_empty() {
            let observed = finding
                .vuln_source
                .unwrap_or_else(|| VulnSource::from_tool(&finding.tool));
            if !self.vuln_source.contains(&observed) {
                return false;
            }
        }

        if let Some(file_path) = &self.file_path {
            let path = finding.file_path.to_ascii_lowercase();
            if !path.contains(file_path) {
                return false;
            }
        }

        true
    }
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
