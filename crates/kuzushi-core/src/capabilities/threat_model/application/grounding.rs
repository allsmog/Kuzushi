use super::*;
use crate::attack_surface::AttackSurface;
use crate::findings::{Finding, FindingListFilter, ProofConfidence};

/// Deterministic evidence handed to the agentic build so the model reasons
/// over ground truth instead of re-deriving the surface from raw inventory.
pub(crate) struct PromptGrounding {
    pub(crate) surfaces: Vec<AttackSurface>,
    pub(crate) confirmed_findings: Vec<ConfirmedFindingRow>,
}

pub(crate) struct ConfirmedFindingRow {
    pub(crate) fingerprint: String,
    pub(crate) title: String,
    pub(crate) file_path: String,
    pub(crate) start_line: u32,
    pub(crate) severity: &'static str,
}

pub(crate) const MAX_CONFIRMED_FINDING_ROWS: usize = 25;

pub(crate) fn load_prompt_grounding(
    input: &BuildInput,
    ctx: &ToolExecutionContext<'_>,
) -> Result<PromptGrounding> {
    Ok(PromptGrounding {
        surfaces: top_ranked_surfaces(&input.target, input.max_elements)?,
        confirmed_findings: confirmed_finding_rows(ctx)?,
    })
}

fn top_ranked_surfaces(target: &Path, max_elements: usize) -> Result<Vec<AttackSurface>> {
    let map = crate::attack_surface::build_attack_surface_map(target)
        .context("threat-model grounding: attack-surface map failed")?;
    let mut surfaces = map.surfaces;
    surfaces.sort_by(|a, b| b.risk.score.cmp(&a.risk.score));
    surfaces.truncate(max_elements.max(1));
    Ok(surfaces)
}

fn confirmed_finding_rows(ctx: &ToolExecutionContext<'_>) -> Result<Vec<ConfirmedFindingRow>> {
    let Some(store) = ctx.findings_store else {
        return Ok(Vec::new());
    };
    // Confirmed = runtime-exploited; Likely = statically-supported
    // (code-cited / source-sink / statically-confirmed). Both are legitimate
    // evidence rows — the band travels with each row so the model can weight
    // them differently.
    let filter = FindingListFilter {
        confidence: vec![ProofConfidence::Confirmed, ProofConfidence::Likely],
        limit: MAX_CONFIRMED_FINDING_ROWS,
        ..Default::default()
    };
    let report = store
        .list_findings_filtered(&filter)
        .context("threat-model grounding: confirmed-findings query failed")?;
    Ok(report.findings.into_iter().map(confirmed_row).collect())
}

fn confirmed_row(finding: Finding) -> ConfirmedFindingRow {
    ConfirmedFindingRow {
        fingerprint: finding.fingerprint,
        title: finding.title,
        file_path: finding.file_path,
        start_line: finding.start_line,
        severity: finding.severity.as_str(),
    }
}

pub(crate) fn attack_surface_section(surfaces: &[AttackSurface]) -> String {
    let body = if surfaces.is_empty() {
        "(no deterministic attack surfaces detected)".to_string()
    } else {
        surfaces
            .iter()
            .map(surface_line)
            .collect::<Vec<_>>()
            .join("\n")
    };
    format!(
        "Deterministic attack-surface map (ground truth: every row below must appear in attackSurface.entryPoints or in deprioritized with a reason):\n{}",
        untrusted_derived_source_block("attack-surface-map", &body)
    )
}

/// Same `<untrusted-source>` armor convention as the source bundle: raw
/// content under a labeled boundary, so file paths and fingerprints stay
/// verbatim-citable (the percent-encoding record frames would mangle `_`,
/// breaking evidence refs and the deterministic coverage match).
pub(crate) fn untrusted_derived_source_block(label: &str, content: &str) -> String {
    format!(
        r#"<untrusted-source label="{label}" kind="derived" path="derived" sha256="{sha256}" truncated="false">
{content}
</untrusted-source>"#,
        sha256 = crate::options::prompt_content_sha256(content),
    )
}

fn surface_line(surface: &AttackSurface) -> String {
    let line = surface
        .line
        .map(|line| format!(":{line}"))
        .unwrap_or_default();
    format!(
        "- {path}{line} · {kind} · {title} · risk={score} ({tier})",
        path = surface.path,
        kind = surface.kind.as_str(),
        title = surface.title,
        score = surface.risk.score,
        tier = surface.risk.tier,
    )
}

pub(crate) fn confirmed_findings_section(rows: &[ConfirmedFindingRow]) -> String {
    if rows.is_empty() {
        return "Corroborated prior findings: none".to_string();
    }
    let body = rows
        .iter()
        .map(finding_line)
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "Corroborated prior findings (confirmed or statically-supported; cite fingerprints in threat evidence — evidence raises likelihood, it is not the threat):\n{}",
        untrusted_derived_source_block("confirmed-findings", &body)
    )
}

fn finding_line(row: &ConfirmedFindingRow) -> String {
    format!(
        "- {fingerprint} · {severity} · {file}:{line} · {title}",
        fingerprint = row.fingerprint,
        severity = row.severity,
        file = row.file_path,
        line = row.start_line,
        title = row.title,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack_surface::{AttackSurfaceKind, AttackSurfaceRisk};

    #[test]
    fn attack_surface_section_renders_ground_truth_rows_in_untrusted_block() {
        let surfaces = vec![AttackSurface {
            id: "s1".to_string(),
            kind: AttackSurfaceKind::HttpRoute,
            path: "src/routes.py".to_string(),
            line: Some(88),
            language: "python".to_string(),
            framework: None,
            title: "GET /admin/debug".to_string(),
            evidence: "@app.route".to_string(),
            method: None,
            route: None,
            boundary: None,
            risk: AttackSurfaceRisk::default(),
            metadata: serde_json::Value::Null,
        }];
        let section = attack_surface_section(&surfaces);
        assert!(section.contains("attack-surface-map"));
        assert!(section.contains("src/routes.py:88"));
        assert!(section.contains("GET /admin/debug"));
        assert!(section.contains("deprioritized"), "coverage rule stated");
    }

    #[test]
    fn confirmed_findings_section_cites_fingerprints_and_evidence_rule() {
        let rows = vec![ConfirmedFindingRow {
            fingerprint: "fp3_abc123".to_string(),
            title: "OOB write in decoder".to_string(),
            file_path: "src/codec.c".to_string(),
            start_line: 42,
            severity: "high",
        }];
        let section = confirmed_findings_section(&rows);
        assert!(section.contains("fp3_abc123"));
        assert!(section.contains("src/codec.c:42"));
        assert!(section.contains("evidence raises likelihood, it is not the threat"));
        assert_eq!(
            confirmed_findings_section(&[]),
            "Corroborated prior findings: none"
        );
    }
}
