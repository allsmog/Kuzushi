use super::prelude::*;
use super::*;

pub(in crate::modules) fn max_findings_option(default: usize) -> OptionSpec {
    opt(
        "maxFindings",
        OptionType::Int,
        "Maximum findings or candidates to return.",
    )
    .default(json!(default))
}

pub(in crate::modules) fn fingerprint_option() -> OptionSpec {
    opt(
        "fingerprint",
        OptionType::String,
        "Finding fingerprint or stable finding alias.",
    )
    .required()
}

pub(in crate::modules) fn binary_option(description: &str) -> OptionSpec {
    opt("binary", OptionType::Path, description).advanced()
}

pub(in crate::modules) fn dag(
    id: &str,
    output_kind: &str,
    depends_on: &[&str],
) -> DagNodeDescriptor {
    DagNodeDescriptor {
        id: id.to_string(),
        output_kind: output_kind.to_string(),
        depends_on: depends_on
            .iter()
            .map(|dependency| dependency.to_string())
            .collect(),
    }
}
