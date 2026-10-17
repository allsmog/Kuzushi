use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SummaryState {
    Current,
    Missing,
    Stale,
    Unreadable,
}

impl SummaryState {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Missing => "missing",
            Self::Stale => "stale",
            Self::Unreadable => "unreadable",
        }
    }

    pub(super) fn message(self) -> String {
        if self == Self::Current {
            return "Markdown summary: current with saved JSON cards.".into();
        }
        format!("Markdown summary: {}. Saved JSON cards remain authoritative. Repair with run threat-leads:build {{\"repairSummary\":true}}; no rescan or model call.", self.label())
    }
}

pub(super) fn inspect_summary(target: &Path, report: &Value) -> SummaryState {
    let path = threat_leads_summary_path(target);
    if std::fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return SummaryState::Missing;
    }
    match crate::workspace::read_workspace_text(target, &path, MAX_THREAT_LEADS_BYTES) {
        Ok(text) => compare_summary(&text, report),
        Err(_) => SummaryState::Unreadable,
    }
}

fn compare_summary(text: &str, report: &Value) -> SummaryState {
    if text == render_threat_leads_markdown(report) {
        SummaryState::Current
    } else {
        SummaryState::Stale
    }
}

pub(super) fn publish(target: &Path, report: &Value) -> Result<Option<String>> {
    publish_with(target, report, &mut |path, bytes| {
        let relative = path
            .strip_prefix(target)
            .context("Threat-leads path escaped the workspace")?;
        crate::workspace::write_workspace_state_file(target, relative, bytes)?;
        Ok(())
    })
}

fn publish_with(
    target: &Path,
    report: &Value,
    write: &mut dyn FnMut(&Path, &[u8]) -> Result<()>,
) -> Result<Option<String>> {
    let artifact = format!("{}\n", serde_json::to_string_pretty(report)?);
    let summary = render_threat_leads_markdown(report);
    ensure_readable_size(&artifact)?;
    ensure_readable_size(&summary)?;
    let artifact_path = threat_leads_artifact_path(target);
    let summary_path = threat_leads_summary_path(target);
    preflight(target, &artifact_path)?;
    preflight(target, &summary_path)?;
    write(&artifact_path, artifact.as_bytes())?;
    Ok(write(&summary_path, summary.as_bytes())
        .err()
        .map(|error| format!("JSON cards were saved; Markdown publication failed: {error:#}")))
}

fn ensure_readable_size(text: &str) -> Result<()> {
    anyhow::ensure!(
        text.len() <= MAX_THREAT_LEADS_BYTES,
        "Threat leads output exceeds its bounded reader; existing artifacts were preserved"
    );
    Ok(())
}

fn preflight(target: &Path, path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => anyhow::ensure!(
            metadata.is_file() && !metadata.is_symlink(),
            "Threat-leads destination must be a regular file, not a directory or symlink"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    crate::workspace::resolve_contained_output_path(target, path)?;
    Ok(())
}

pub(super) fn repair(target: &Path, report: &Value) -> Result<()> {
    let path = threat_leads_summary_path(target);
    let summary = render_threat_leads_markdown(report);
    ensure_readable_size(&summary)?;
    preflight(target, &path)?;
    let relative = path
        .strip_prefix(target)
        .context("Threat-leads summary escaped the workspace")?;
    crate::workspace::write_workspace_state_file(target, relative, summary.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests;
