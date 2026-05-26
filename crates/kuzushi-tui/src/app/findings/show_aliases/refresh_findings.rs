use super::*;

impl ShellApp {
    pub(crate) fn refresh_findings(&mut self, announce: bool) {
        let store = match self.open_store() {
            Ok(store) => store,
            Err(error) => {
                self.log_refresh_findings_error(error, announce);
                return;
            }
        };

        match store.list_findings(200) {
            Ok(findings) => self.replace_findings(findings, announce),
            Err(error) => self.log_refresh_findings_error(error.into(), announce),
        }
    }

    fn replace_findings(&mut self, findings: Vec<Finding>, announce: bool) {
        self.findings = findings;
        self.reselect_current_finding();
        self.clamp_findings_cursor();
        if announce {
            let count = self.findings.len();
            self.log(
                "findings",
                format!(
                    "loaded {} {}",
                    count,
                    if count == 1 { "finding" } else { "findings" }
                ),
            );
        }
    }

    fn reselect_current_finding(&mut self) {
        let Some(selected) = &self.selected_finding else {
            return;
        };
        self.selected_finding = self
            .findings
            .iter()
            .find(|finding| finding.fingerprint == selected.fingerprint)
            .cloned();
    }

    fn log_refresh_findings_error(&mut self, error: anyhow::Error, announce: bool) {
        if announce {
            self.log(
                "error",
                with_next_step(error.to_string(), "scan <target> or workspace status"),
            );
        }
    }
}
