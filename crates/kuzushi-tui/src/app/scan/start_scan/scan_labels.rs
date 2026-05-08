use super::*;

impl ShellApp {
    pub(crate) fn scan_target_label(&self) -> String {
        self.target
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| ".".to_string())
    }

    pub(crate) fn log_scan_alias_hint(&mut self) {
        if let Some((alias, finding)) = sorted_finding_aliases(&self.findings).into_iter().next() {
            self.log(
                "scan",
                format!(
                    "top alias {alias} -> {} ({})",
                    short_fingerprint(&finding.fingerprint),
                    truncate_ascii(&finding.title, 64)
                ),
            );
        }
    }
}
