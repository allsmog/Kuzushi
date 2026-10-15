use super::*;

pub(in crate::modules) fn bound_threat_model_digest_option() -> OptionSpec {
    opt("threatModelDigestRef", OptionType::Json,
        "Exact saved agentic/triage threat-model text for this source and context revision. Finite model-backed studies freeze it before approval; missing or mismatched bytes refuse execution.")
        .advanced()
}

pub(in crate::modules) fn bound_scan_context_option() -> OptionSpec {
    opt("scanContextRef", OptionType::Json,
        "Frozen supporting repository context for agentic discovery; null omits this supplement. Study preparation captures an authenticated immutable reference. Other adapters do not consume this supplement.")
        .aliases(&["scan_context_ref"]).advanced()
}

pub(in crate::modules) fn bound_threat_model_option() -> OptionSpec {
    opt(
        "threatModelRef",
        OptionType::Json,
        "Immutable threat-model revision to consume without changing the active model; null explicitly omits threat-model context.",
    )
    .aliases(&["threat_model_ref"])
    .advanced()
}
