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
