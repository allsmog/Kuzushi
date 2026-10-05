use super::*;

pub(in crate::modules) fn bound_threat_model_option() -> OptionSpec {
    opt(
        "threatModelRef",
        OptionType::Json,
        "Immutable threat-model revision to consume without changing the active model; null explicitly omits threat-model context.",
    )
    .aliases(&["threat_model_ref"])
    .advanced()
}
