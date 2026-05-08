use super::*;

pub(crate) fn module_category(kind: ModuleKind) -> (&'static str, &'static str) {
    match kind {
        ModuleKind::Offense | ModuleKind::Scan => {
            ("OFFENSE", "hunt vulnerabilities and prove exploitability")
        }
        ModuleKind::Intel | ModuleKind::Context | ModuleKind::Workspace => {
            ("INTEL", "map target context and workspace state")
        }
        ModuleKind::Governance | ModuleKind::Config | ModuleKind::Catalog => (
            "GOVERNANCE",
            "configuration, inventory, and operator controls",
        ),
        ModuleKind::Defense | ModuleKind::Findings | ModuleKind::Triage => {
            ("DEFENSE", "prioritize, triage, and remediate findings")
        }
        ModuleKind::Internal => ("GOVERNANCE", "internal orchestration"),
    }
}

pub(crate) fn module_category_blurb(category: &str) -> (&'static str, &'static str) {
    match category {
        "OFFENSE" => (
            "OFFENSE",
            "find vulnerabilities by scanning code, dependencies, and runtime surface",
        ),
        "INTEL" => (
            "INTEL",
            "build context, recon, and threat model the operator reads first",
        ),
        "GOVERNANCE" => ("GOVERNANCE", "configuration, allowlists, and audit trails"),
        "DEFENSE" => ("DEFENSE", "triage, verify, and patch emitted findings"),
        _ => ("OTHER", "loaded module surfaces"),
    }
}
