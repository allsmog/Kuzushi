use super::*;

impl ShellApp {
    pub fn first_finding_scan_command(&self) -> &'static str {
        if self.target().is_some() {
            "next"
        } else {
            "target .; next"
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
            .target()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "none".to_string());
        let module_count = self.registry().discoverable_modules().count();
        let tool_count = self.registry().discoverable_tools().count();
        format!(
            "ready: {module_count} {}, {tool_count} {}, target {target}",
            pluralize(module_count, "module", "modules"),
            pluralize(tool_count, "tool", "tools"),
        )
    }
}

fn pluralize(count: usize, singular: &'static str, plural: &'static str) -> &'static str {
    if count == 1 {
        singular
    } else {
        plural
    }
}
