use super::*;
use crate::workspace::inventory::SourcePrefixes;

pub(super) fn context_output(
    prefixes: SourcePrefixes,
    max_surfaces: usize,
    canceled: &dyn Fn() -> bool,
) -> Result<SystemsContextOutput> {
    let (mut ranked, clipped) = rank_prefixes(&prefixes.files, canceled)?;
    ranked.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.file_path.cmp(&right.file_path))
    });
    let omitted = ranked.len().saturating_sub(max_surfaces);
    ranked.truncate(max_surfaces);
    let (surface_packs, limited_packs) = packs::from_prefixes(&ranked, &prefixes.files, canceled)?;
    let receipt = inspection(
        prefixes.coverage,
        clipped,
        limited_packs,
        omitted,
        max_surfaces,
    );
    Ok(SystemsContextOutput {
        surfaces: ranked,
        surface_packs,
        metadata: SystemsContextMetadata {
            codeql_available: false,
            codeql_db_path: None,
            bash_probing_used: false,
            systems_source_files: prefixes.files.len(),
            inspection: Some(receipt),
        },
    })
}

fn rank_prefixes(
    files: &[SourcePrefix],
    canceled: &dyn Fn() -> bool,
) -> Result<(Vec<RankedSystemsSurface>, usize)> {
    let mut ranked = Vec::new();
    let mut clipped = 0;
    for file in files {
        anyhow::ensure!(!canceled(), "systems context ranking canceled");
        if let Some((surface, limited)) = rank_file(file) {
            clipped += usize::from(limited);
            ranked.push(surface);
        }
    }
    Ok((ranked, clipped))
}

fn rank_file(file: &SourcePrefix) -> Option<(RankedSystemsSurface, bool)> {
    let mut accumulator = None;
    let mut clipped = false;
    for (index, line) in file.text.lines().enumerate() {
        let signals = classify_line(line);
        if signals.is_empty() {
            continue;
        }
        let surface = accumulator.get_or_insert_with(|| {
            SurfaceAccumulator::new(
                file.relative.clone(),
                infer_kind(&file.relative, line),
                (index + 1) as u32,
            )
        });
        clipped |= record_signals(surface, line, (index + 1) as u32, signals);
    }
    accumulator.map(|surface| (surface.finish(), clipped))
}

fn record_signals(
    surface: &mut SurfaceAccumulator,
    line: &str,
    line_number: u32,
    signals: Vec<(&str, &str, i64)>,
) -> bool {
    let mut clipped = false;
    for (domain, reason, weight) in signals {
        surface.score += weight;
        surface.domains.insert(domain.into());
        surface.reasons.insert(reason.into());
        clipped |= push_evidence(surface, domain, reason, line_number, line);
    }
    surface
        .attacker_controlled_fields
        .extend(attacker_fields(line));
    if contains_any(
        &line.to_ascii_lowercase(),
        &[
            "checked_",
            "saturating_",
            "validate",
            "guard",
            "assert",
            "bounds",
        ],
    ) {
        clipped |= record_hardening(surface, line);
    }
    clipped
}

fn push_evidence(
    surface: &mut SurfaceAccumulator,
    domain: &str,
    reason: &str,
    line_number: u32,
    line: &str,
) -> bool {
    if surface.evidence.len() >= 12 {
        return true;
    }
    surface.evidence.push(SystemsSurfaceSignal {
        domain: domain.into(),
        line_number,
        line_content: clip_line(line),
        reason: reason.into(),
    });
    false
}

fn record_hardening(surface: &mut SurfaceAccumulator, line: &str) -> bool {
    let text = clip_line(line);
    if surface.hardening_signals.contains(&text) {
        return false;
    }
    if surface.hardening_signals.len() >= 12 {
        return true;
    }
    surface.hardening_signals.insert(text);
    false
}

pub(super) fn clip_line(line: &str) -> String {
    line.trim().chars().take(240).collect()
}

fn inspection(
    mut receipt: Value,
    evidence: usize,
    packs: usize,
    omitted: usize,
    max: usize,
) -> Value {
    receipt["ranking"] = json!("deterministic lexical signals; not vulnerability verdicts");
    receipt["codeIndex"] = json!("not_requested");
    receipt["codeqlInspection"] = json!("not_requested");
    receipt["maxEvidenceSignalsPerFile"] = json!(12);
    receipt["maxEvidenceLineChars"] = json!(240);
    receipt["evidenceLimitedFiles"] = json!(evidence);
    receipt["maxSitesPerCategory"] = json!(12);
    receipt["siteLimitedPacks"] = json!(packs);
    receipt["maxSurfaces"] = json!(max);
    receipt["omittedSurfaces"] = json!(omitted);
    if evidence + packs + omitted > 0 {
        receipt["status"] = json!("partial");
    }
    receipt
}
