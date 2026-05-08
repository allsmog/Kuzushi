use super::*;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FindingListReport {
    pub count: usize,
    pub findings: Vec<Finding>,
}

impl FindingListReport {
    pub fn output(&self) -> String {
        if self.findings.is_empty() {
            return "  (no findings match)".to_string();
        }

        let aliased = sorted_finding_aliases(&self.findings);
        let alias_width = aliased
            .iter()
            .map(|(alias, _)| alias.len())
            .max()
            .unwrap_or(5)
            .max(5);
        let fingerprint_width = aliased
            .iter()
            .map(|(_, finding)| short_id(&finding.fingerprint).len())
            .max()
            .unwrap_or(8)
            .max(8);
        let severity_width = self
            .findings
            .iter()
            .map(|finding| finding.severity.as_str().len())
            .max()
            .unwrap_or(4)
            .max(4);
        let verdict_width = self
            .findings
            .iter()
            .map(|finding| {
                FindingVerdictFilter::from_finding(finding)
                    .as_legacy_str()
                    .len()
            })
            .max()
            .unwrap_or(5)
            .max(5);
        let name_width = self
            .findings
            .iter()
            .map(|finding| finding.title.len())
            .max()
            .unwrap_or(4)
            .max(4);

        let mut lines = vec![
            format!(
                "  {}  {}  {}  {}  {}",
                pad("Alias", alias_width),
                pad("Fingerprint", fingerprint_width),
                pad("Sev", severity_width),
                pad("Check", verdict_width),
                pad("Name", name_width)
            ),
            format!(
                "  {}  {}  {}  {}  {}",
                "-".repeat(alias_width),
                "-".repeat(fingerprint_width),
                "-".repeat(severity_width),
                "-".repeat(verdict_width),
                "-".repeat(name_width)
            ),
        ];

        for (alias, finding) in aliased {
            lines.push(format!(
                "  {}  {}  {}  {}  {}",
                pad(&alias, alias_width),
                pad(&short_id(&finding.fingerprint), fingerprint_width),
                pad(finding.severity.as_str(), severity_width),
                pad(
                    FindingVerdictFilter::from_finding(&finding).as_legacy_str(),
                    verdict_width
                ),
                finding.title
            ));
        }

        lines.push(String::new());
        lines.push(format!(
            "  {} matching (showing {})",
            self.count,
            self.findings.len()
        ));
        lines.join("\n")
    }

    pub fn to_tool_json(&self) -> Value {
        json!({
            "ok": true,
            "output": self.output(),
            "data": self,
        })
    }
}

pub fn format_finding_alias(index: usize) -> String {
    format!("F-{:04}", index + 1)
}

pub fn parse_finding_alias(reference: &str) -> Option<usize> {
    let reference = reference.trim();
    let suffix = reference
        .strip_prefix("F-")
        .or_else(|| reference.strip_prefix("f-"))?;
    let index = suffix.parse::<usize>().ok()?;
    index.checked_sub(1)
}
