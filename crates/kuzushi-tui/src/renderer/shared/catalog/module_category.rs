pub(crate) fn module_category_blurb(category: &str) -> (&'static str, &'static str) {
    match category {
        "OFFENSE" => (
            "HUNT",
            "scan code, dependencies, and runtime surface for candidates",
        ),
        "INTEL" => (
            "MAP",
            "build context, recon, inventory, and threat model first",
        ),
        "GOVERNANCE" => (
            "OPERATE",
            "configure providers, catalogs, policy, and audit trails",
        ),
        "DEFENSE" => ("CONFIRM/FIX", "triage, verify, patch, and report findings"),
        _ => ("OTHER", "loaded module surfaces"),
    }
}
