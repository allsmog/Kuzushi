#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RunReferenceResolution {
    Resolved(String),
    Ambiguous(Vec<String>),
    Missing,
}

pub(crate) fn compact_run_reference(run_id: &str) -> String {
    let chars = run_id.chars().collect::<Vec<_>>();
    if chars.len() <= 8 {
        return run_id.to_string();
    }
    chars[chars.len() - 8..].iter().collect()
}

pub(crate) fn resolve_run_reference<'a>(
    reference: &str,
    candidates: impl IntoIterator<Item = &'a str>,
) -> RunReferenceResolution {
    let reference = reference.trim().trim_matches('…');
    let candidates = candidates.into_iter().collect::<Vec<_>>();
    if let Some(exact) = candidates.iter().find(|candidate| **candidate == reference) {
        return RunReferenceResolution::Resolved((*exact).to_string());
    }
    if reference.len() < 4 {
        return RunReferenceResolution::Missing;
    }
    let matches = candidates
        .into_iter()
        .filter(|candidate| reference_matches_candidate(reference, candidate))
        .map(str::to_string)
        .collect();
    resolution_from_matches(matches)
}

fn reference_matches_candidate(reference: &str, candidate: &str) -> bool {
    candidate.starts_with(reference)
        || candidate.ends_with(reference)
        || compact_run_reference(candidate) == reference
}

fn resolution_from_matches(mut matches: Vec<String>) -> RunReferenceResolution {
    matches.sort();
    matches.dedup();
    match matches.len() {
        0 => RunReferenceResolution::Missing,
        1 => RunReferenceResolution::Resolved(matches.remove(0)),
        _ => RunReferenceResolution::Ambiguous(matches),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_suffix_resolves_and_ambiguous_prefix_does_not() {
        let ids = ["tool-12345678-aaaa1111", "tool-12345678-bbbb2222"];
        assert_eq!(
            resolve_run_reference("bbbb2222", ids),
            RunReferenceResolution::Resolved(ids[1].to_string())
        );
        assert!(matches!(
            resolve_run_reference("tool-1234", ids),
            RunReferenceResolution::Ambiguous(_)
        ));
    }
}
