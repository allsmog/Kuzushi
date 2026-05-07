use std::path::PathBuf;

use anyhow::Result;
use kuzushi_core::{
    format_finding_alias, parse_finding_alias, resolve_finding_alias, sorted_finding_aliases,
    Finding, FindingStore, WorkspaceTarget,
};

use super::{with_next_step, ExploitChain, ShellApp, ShellView};

impl ShellApp {
    pub fn show_aliases(&mut self, prefix: Option<&str>) {
        self.shell_view = ShellView::Findings;
        let filter = prefix.map(|raw| raw.trim().to_ascii_uppercase());
        let table = format_alias_table(&self.findings, &self.chains, filter.as_deref());
        for line in table.lines() {
            self.log("aliases", line.to_string());
        }
    }

    pub(super) fn show_findings(&mut self) {
        self.shell_view = ShellView::Findings;
        self.refresh_findings(true);
        self.clamp_findings_cursor();
        if self.findings.is_empty() {
            self.log("findings", "no findings yet. Next: scan or scan <target>");
        }
    }

    pub(super) fn clamp_findings_cursor(&mut self) {
        if self.findings.is_empty() {
            self.findings_cursor = 0;
        } else {
            self.findings_cursor = self.findings_cursor.min(self.findings.len() - 1);
        }
    }

    pub(super) fn open_finding_at_cursor(&mut self) {
        let aliases = sorted_finding_aliases(&self.findings);
        if aliases.is_empty() {
            return;
        }
        let cursor = self.findings_cursor.min(aliases.len() - 1);
        let (alias, finding) = aliases[cursor].clone();
        self.findings_cursor = cursor;
        self.selected_finding = Some(finding.clone());
        self.shell_view = ShellView::Finding;
        self.log(
            "open",
            format!(
                "{alias} {} {}:{} {}",
                finding.severity.as_str(),
                finding.file_path,
                finding.start_line,
                finding.fingerprint
            ),
        );
        self.log("title", finding.title);
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

    pub(super) fn open_finding(&mut self, reference: &str) {
        if let Some(index) = parse_chain_alias(reference) {
            let Some(chain) = self.chains.get(index) else {
                self.log(
                    "error",
                    format!(
                        "no chain alias {} is available. Next: /show aliases",
                        format_chain_alias(index)
                    ),
                );
                return;
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
            return;
        }

        let reference = if let Some(index) = parse_finding_alias(reference) {
            self.refresh_findings(false);
            let Some(finding) = resolve_finding_alias(&self.findings, reference) else {
                self.log(
                    "error",
                    format!(
                        "no finding alias {} is available. Next: findings",
                        format_finding_alias(index)
                    ),
                );
                return;
            };
            finding.fingerprint.clone()
        } else {
            reference.to_string()
        };

        let store = match self.open_store() {
            Ok(store) => store,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };

        match store.get_finding_by_reference(&reference) {
            Ok(Some(finding)) => {
                self.selected_finding = Some(finding.clone());
                self.shell_view = ShellView::Finding;
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
                self.log("title", finding.title);
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
            Ok(None) => self.log(
                "error",
                format!("no finding matches {reference:?}. Next: findings or scan"),
            ),
            Err(error) => self.log(
                "error",
                with_next_step(error.to_string(), "findings or scan <target>"),
            ),
        }
    }

    pub(super) fn refresh_findings(&mut self, announce: bool) {
        let store = match self.open_store() {
            Ok(store) => store,
            Err(error) => {
                if announce {
                    self.log(
                        "error",
                        with_next_step(error.to_string(), "scan <target> or workspace status"),
                    );
                }
                return;
            }
        };

        match store.list_findings(200) {
            Ok(findings) => {
                self.findings = findings;
                if let Some(selected) = &self.selected_finding {
                    self.selected_finding = self
                        .findings
                        .iter()
                        .find(|finding| finding.fingerprint == selected.fingerprint)
                        .cloned();
                }
                self.clamp_findings_cursor();
                if announce {
                    self.log(
                        "findings",
                        format!("loaded {} finding(s)", self.findings.len()),
                    );
                }
            }
            Err(error) => {
                if announce {
                    self.log(
                        "error",
                        with_next_step(error.to_string(), "scan <target> or workspace status"),
                    );
                }
            }
        }
    }

    pub(crate) fn open_store(&mut self) -> Result<FindingStore> {
        let workspace = self.current_workspace()?;
        let resolved = workspace.root().to_path_buf();
        // Surface the implicit target assignment so the operator isn't
        // surprised by `target none` flipping to a real path the moment
        // they type `findings`. We log on the first transition only.
        if self.target.as_deref() != Some(resolved.as_path()) {
            self.log(
                "target",
                format!("set to {} (implied from cwd)", resolved.display()),
            );
        }
        self.target = Some(resolved);
        FindingStore::open(workspace.findings_db_path())
    }

    pub(super) fn current_workspace(&self) -> Result<WorkspaceTarget> {
        let target = self.target.clone().unwrap_or_else(|| PathBuf::from("."));
        WorkspaceTarget::new(target)
    }

    pub(super) fn explicit_workspace(&self) -> Result<WorkspaceTarget> {
        let Some(target) = self.target.clone() else {
            anyhow::bail!(
                "workspace export requires an active workspace. Next: scan <target> or start shell with --target ."
            );
        };
        WorkspaceTarget::new(target)
    }
}

pub fn format_chain_alias(index: usize) -> String {
    format!("C-{:02}", index + 1)
}

pub fn parse_chain_alias(reference: &str) -> Option<usize> {
    let reference = reference.trim();
    let suffix = reference
        .strip_prefix("C-")
        .or_else(|| reference.strip_prefix("c-"))?;
    let index = suffix.parse::<usize>().ok()?;
    index.checked_sub(1)
}

pub(crate) fn sorted_chain_aliases(chains: &[ExploitChain]) -> Vec<(String, ExploitChain)> {
    let mut indexed: Vec<&ExploitChain> = chains.iter().collect();
    indexed.sort_by(|a, b| {
        let by_severity = a.severity.rank().cmp(&b.severity.rank());
        if by_severity == std::cmp::Ordering::Equal {
            a.id.cmp(&b.id)
        } else {
            by_severity
        }
    });
    indexed
        .into_iter()
        .enumerate()
        .map(|(index, chain)| (format_chain_alias(index), chain.clone()))
        .collect()
}

pub fn format_alias_table(
    findings: &[Finding],
    chains: &[ExploitChain],
    filter: Option<&str>,
) -> String {
    let chain_aliases = sorted_chain_aliases(chains);
    let finding_aliases = sorted_finding_aliases(findings);
    let mut rows: Vec<(String, String, String)> = Vec::new();
    for (alias, chain) in &chain_aliases {
        if let Some(prefix) = filter {
            if !alias.to_ascii_uppercase().starts_with(prefix) {
                continue;
            }
        }
        rows.push((alias.clone(), chain.id.clone(), chain.title.clone()));
    }
    for (alias, finding) in &finding_aliases {
        if let Some(prefix) = filter {
            if !alias.to_ascii_uppercase().starts_with(prefix) {
                continue;
            }
        }
        let target = finding.fingerprint.chars().take(12).collect::<String>();
        rows.push((alias.clone(), target, finding.title.clone()));
    }
    if rows.is_empty() {
        return match filter {
            Some(prefix) => format!("No aliases match \"{prefix}\""),
            None => "No aliases for the current run".to_string(),
        };
    }
    let alias_w = rows
        .iter()
        .map(|(a, _, _)| a.len())
        .max()
        .unwrap_or(0)
        .max(5);
    let target_w = rows
        .iter()
        .map(|(_, t, _)| t.len())
        .max()
        .unwrap_or(0)
        .max(6);
    let mut lines = Vec::new();
    lines.push(format!(
        "{:<alias_w$}  {:<target_w$}  title",
        "alias", "target",
    ));
    lines.push(format!("{:─<alias_w$}  {:─<target_w$}  ─────", "", "",));
    for (alias, target, title) in rows {
        lines.push(format!("{alias:<alias_w$}  {target:<target_w$}  {title}",));
    }
    lines.join("\n")
}

pub(super) fn short_fingerprint(fingerprint: &str) -> String {
    fingerprint.chars().take(8).collect()
}
