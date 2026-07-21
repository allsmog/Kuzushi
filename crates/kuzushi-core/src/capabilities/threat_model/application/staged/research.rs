use super::super::*;
use crate::workspace::{
    mine_vuln_history, security_keywords_for_languages, GitHistoryMiningConfig, VulnCommit,
};

/// Stage R output: deterministic, zero-cost evidence for the synthesis call
/// plus the evidence index that later validates every ref the model cites.
pub(crate) struct ResearchDossier {
    pub(crate) grounding: PromptGrounding,
    pub(crate) vuln_commits: Vec<VulnCommit>,
    pub(crate) history_mined: bool,
    pub(crate) evidence_index: BTreeSet<String>,
}

pub(crate) fn run_research(
    input: &BuildInput,
    ctx: &ToolExecutionContext<'_>,
) -> Result<ResearchDossier> {
    let grounding = load_prompt_grounding(input, ctx)?;
    let mined = mine_history(input, &grounding)?;
    let history_mined = mined.is_some();
    let vuln_commits = mined.unwrap_or_default();
    let evidence_index = build_evidence_index(&grounding, &vuln_commits);
    Ok(ResearchDossier {
        grounding,
        vuln_commits,
        history_mined,
        evidence_index,
    })
}

fn mine_history(
    input: &BuildInput,
    grounding: &PromptGrounding,
) -> Result<Option<Vec<VulnCommit>>> {
    let languages: BTreeSet<String> = grounding
        .surfaces
        .iter()
        .map(|surface| surface.language.clone())
        .collect();
    let keywords =
        security_keywords_for_languages(languages.iter().map(String::as_str));
    let cfg = GitHistoryMiningConfig {
        max_commits: input.history_depth,
        ..Default::default()
    };
    mine_vuln_history(&input.target, &keywords, &cfg)
}

fn build_evidence_index(
    grounding: &PromptGrounding,
    commits: &[VulnCommit],
) -> BTreeSet<String> {
    let mut index = BTreeSet::new();
    for finding in &grounding.confirmed_findings {
        index.insert(finding.fingerprint.clone());
        index.insert(format!("{}:{}", finding.file_path, finding.start_line));
    }
    for surface in &grounding.surfaces {
        if let Some(line) = surface.line {
            index.insert(format!("{}:{line}", surface.path));
        }
    }
    for commit in commits {
        index.insert(commit.sha.clone());
        if commit.sha.len() >= 12 {
            index.insert(commit.sha[..12].to_string());
        }
    }
    index
}

/// Prompt section for mined security-fix history; empty when nothing was
/// mined so the section joiner drops it.
pub(crate) fn vuln_commits_section(commits: &[VulnCommit]) -> String {
    if commits.is_empty() {
        return String::new();
    }
    let mut body = commits
        .iter()
        .map(|commit| format!("- {} · {}", commit.sha, commit.subject))
        .collect::<Vec<_>>()
        .join("\n");
    for commit in commits.iter().filter(|c| c.diff_excerpt.is_some()) {
        body.push_str(&format!(
            "\n\n=== diff excerpt {} ===\n{}",
            commit.sha,
            commit.diff_excerpt.as_deref().unwrap_or_default()
        ));
    }
    format!(
        "Mined security-fix history (past vulns to generalize into threat classes; cite commit shas as evidence refs):\n{}",
        untrusted_derived_source_block("vuln-history", &body)
    )
}

pub(crate) fn research_stats(dossier: &ResearchDossier) -> Value {
    json!({
        "surfaces": dossier.grounding.surfaces.len(),
        "confirmedFindings": dossier.grounding.confirmed_findings.len(),
        "vulnCommits": dossier.vuln_commits.len(),
        "historyMined": dossier.history_mined,
        "diffExcerpts": dossier
            .vuln_commits
            .iter()
            .filter(|commit| commit.diff_excerpt.is_some())
            .count(),
        "evidenceIndexSize": dossier.evidence_index.len(),
    })
}

pub(crate) fn research_artifact_json(dossier: &ResearchDossier) -> Value {
    json!({
        "stats": research_stats(dossier),
        "surfaces": dossier
            .grounding
            .surfaces
            .iter()
            .map(|surface| json!({
                "path": surface.path,
                "line": surface.line,
                "kind": surface.kind.as_str(),
                "title": surface.title,
                "riskScore": surface.risk.score,
            }))
            .collect::<Vec<_>>(),
        "confirmedFindings": dossier
            .grounding
            .confirmed_findings
            .iter()
            .map(|finding| json!({
                "fingerprint": finding.fingerprint,
                "file": finding.file_path,
                "line": finding.start_line,
                "severity": finding.severity,
                "title": finding.title,
            }))
            .collect::<Vec<_>>(),
        "vulnCommits": dossier
            .vuln_commits
            .iter()
            .map(|commit| json!({
                "sha": commit.sha,
                "subject": commit.subject,
                "hasDiffExcerpt": commit.diff_excerpt.is_some(),
            }))
            .collect::<Vec<_>>(),
    })
}
