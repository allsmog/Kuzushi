use super::super::*;
use super::advisories::advisories_section;
use super::research::{project_docs_section, vuln_commits_section, ResearchDossier};

/// Stage S prompt: the grounded single-call prompt plus the mined vuln
/// history and the synthesis contract (reference stages 2+3 — map vulns to
/// entry points, cluster into patch-surviving threat classes, cite evidence
/// only by dossier ref, emit variant-scan patterns).
pub(crate) fn staged_synthesis_prompt(
    input: &BuildInput,
    source_bundle: &ThreatModelSourceBundle,
    dossier: &ResearchDossier,
) -> Result<String> {
    // The seeding decision resolved at the adapter: fresh — or a sources list
    // that excludes the persisted model — embeds nothing from the previous
    // generation, full document and count summary alike.
    let previous_model = if input.embeds_prior_model() {
        load_selected_build_threat_model(input)?.map(|selected| selected.document)
    } else {
        None
    };
    let base = build_agent_prompt(
        input,
        previous_model.as_ref(),
        source_bundle,
        &dossier.grounding,
    )?;
    Ok([
        base,
        project_docs_section(&dossier.docs),
        vuln_commits_section(&dossier.vuln_commits),
        advisories_section(&dossier.advisories),
        SYNTHESIS_CONTRACT.to_string(),
    ]
    .into_iter()
    .filter(|section| !section.trim().is_empty())
    .collect::<Vec<_>>()
    .join("\n\n"))
}

const SYNTHESIS_CONTRACT: &str = r#"Staged synthesis contract (in addition to everything above):
1. Map every mined security-fix commit and every confirmed prior finding to the entry point it traversed. If that entry point is missing from the deterministic attack-surface map, add it to attackSurface.entryPoints — a past vuln proves the surface exists.
2. Cluster past vulns by (entry point, bug class, asset reached); emit ONE threat per cluster. Litmus test: the threat statement must remain true after every cited evidence item is patched — if not, you are still at vuln level; zoom out.
3. threats[].evidence entries must be objects {"kind": "finding"|"commit"|"advisory"|"code", "ref": "<verbatim fingerprint, commit sha, or file:line copied from the sections above>", "summary": "<one line>"}. Refs that do not appear verbatim in the research sections are dropped by a deterministic validator — do not invent them. Threats derived purely from analysis get an empty evidence array; that is expected and required for gap coverage.
4. threats[].variantScan = {"patterns": ["<1-3 grep-able code patterns that would locate sibling instances of this class>"]}. Do not estimate sibling counts yourself; a deterministic scan counts them.
5. Evidence raises likelihood; it is not the threat. Score likelihood as residual after existing mitigations."#;
