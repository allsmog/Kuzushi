use super::*;

impl ShellApp {
    pub(crate) fn scan_target_label(&self) -> String {
        self.scan_target_owned()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "no target".to_string())
    }

    pub(crate) fn scan_target_owned(&self) -> Option<PathBuf> {
        self.scan()
            .map(|scan| scan.target.clone())
            .or_else(|| self.target_owned())
    }

    pub(crate) fn log_scan_alias_hint(&mut self) {
        if let Some((alias, index)) = kuzushi_core::sorted_finding_alias_indices(self.findings())
            .into_iter()
            .next()
        {
            let Some(finding) = self.findings().get(index) else {
                return;
            };
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
