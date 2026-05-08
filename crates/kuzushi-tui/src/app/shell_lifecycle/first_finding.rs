use super::*;

impl ShellApp {
    pub fn first_finding_scan_command(&self) -> &'static str {
        if self.target.is_some() {
            "scan"
        } else {
            "scan ."
        }
    }

    pub fn first_finding_hint(&self) -> String {
        format!(
            "First finding: run `{}`, then `findings`.",
            self.first_finding_scan_command()
        )
    }

    pub(crate) fn startup_summary_line(&self) -> String {
        let target = self
            .target
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "none".to_string());
        format!(
            "ready: {} module(s), {} tool(s), target {target}",
            self.registry.modules().count(),
            self.registry.tools().count()
        )
    }
}
