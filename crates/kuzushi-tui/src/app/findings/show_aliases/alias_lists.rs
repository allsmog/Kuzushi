use super::*;

impl ShellApp {
    pub fn show_aliases(&mut self, prefix: Option<&str>) {
        self.shell_view = ShellView::Findings;
        let filter = prefix.map(|raw| raw.trim().to_ascii_uppercase());
        let table = format_alias_table(&self.findings, &self.chains, filter.as_deref());
        for line in table.lines() {
            self.log("aliases", line.to_string());
        }
    }

    pub(crate) fn show_findings(&mut self) {
        self.shell_view = ShellView::Findings;
        self.refresh_findings(true);
        self.clamp_findings_cursor();
        if self.findings.is_empty() {
            self.log("findings", "no findings yet. Next: scan or scan <target>");
        }
    }

    pub(crate) fn clamp_findings_cursor(&mut self) {
        if self.findings.is_empty() {
            self.findings_cursor = 0;
        } else {
            self.findings_cursor = self.findings_cursor.min(self.findings.len() - 1);
        }
    }
}
