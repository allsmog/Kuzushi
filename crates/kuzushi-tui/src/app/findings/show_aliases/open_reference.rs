use super::*;

impl ShellApp {
    pub(crate) fn open_finding(&mut self, reference: &str) {
        if self.open_chain_alias(reference) {
            return;
        }

        let Some(reference) = self.resolve_open_finding_reference(reference) else {
            return;
        };
        let store = match self.open_store() {
            Ok(store) => store,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        self.apply_open_finding_result(&reference, store.get_finding_by_reference(&reference));
    }

    fn open_chain_alias(&mut self, reference: &str) -> bool {
        let Some(index) = parse_chain_alias(reference) else {
            return false;
        };
        let Some(chain) = self.chains.get(index) else {
            self.log(
                "error",
                format!(
                    "no chain alias {} is available. Next: /show aliases",
                    format_chain_alias(index)
                ),
            );
            return true;
        };
        self.log(
            "open",
            format!(
                "chain {} ({}) — {}",
                chain.id,
                chain.severity.label(),
                chain.title
            ),
        );
        true
    }

    fn resolve_open_finding_reference(&mut self, reference: &str) -> Option<String> {
        let Some(index) = parse_finding_alias(reference) else {
            return Some(reference.to_string());
        };
        self.refresh_findings(false);
        let Some(finding) = resolve_finding_alias(&self.findings, reference) else {
            self.log(
                "error",
                format!(
                    "no finding alias {} is available. Next: findings",
                    format_finding_alias(index)
                ),
            );
            return None;
        };
        Some(finding.fingerprint.clone())
    }

    fn apply_open_finding_result(
        &mut self,
        reference: &str,
        result: Result<Option<Finding>, anyhow::Error>,
    ) {
        match result {
            Ok(result) => self.apply_found_finding(reference, result),
            Err(error) => self.log_open_finding_error(error),
        }
    }

    fn apply_found_finding(&mut self, reference: &str, finding: Option<Finding>) {
        let Some(finding) = finding else {
            self.log(
                "error",
                format!("no finding matches {reference:?}. Next: findings or scan"),
            );
            return;
        };
        self.selected_finding = Some(finding.clone());
        self.shell_view = ShellView::Finding;
        self.log_opened_finding(&finding);
    }

    fn log_opened_finding(&mut self, finding: &Finding) {
        self.log(
            "open",
            format!(
                "{} {}:{} {}",
                finding.severity.as_str(),
                finding.file_path,
                finding.start_line,
                finding.fingerprint
            ),
        );
        self.log("title", finding.title.clone());
        if let Some(triage) = &finding.triage {
            self.log(
                "triage",
                format!(
                    "{} {:.2} {}",
                    triage.verdict.as_str(),
                    triage.confidence,
                    triage.rationale
                ),
            );
        }
    }

    fn log_open_finding_error(&mut self, error: anyhow::Error) {
        self.log(
            "error",
            with_next_step(error.to_string(), "findings or scan <target>"),
        );
    }
}
