use super::*;

pub(super) fn generation_tool() -> ToolDescriptor {
    hidden_tool_with_options("taint-iris-next:catalog",
        "Experimental source-grounded catalog draft. One model turn with no tools or repair. Requires Context allowance; saves a draft and changes no active catalog or phase.", generation_options())
        .with_policy(workspace_policy(ToolPhase::Map, RuntimeRequirement::Always, FindingStoreRequirement::Optional))
        .with_allowance_category(AllowanceCategory::Context).without_phase_result().with_discovery_maturity(ModuleMaturity::Labs)
        .with_prompt(editable_prompt("catalog generation", "taint-iris-next", "catalog", "TAINT_IRIS_NEXT_CATALOG_PROMPT",
            crate::capabilities::taint_iris_next::TAINT_IRIS_NEXT_CATALOG_SYSTEM_PROMPT.into()))
}

fn generation_options() -> Vec<OptionSpec> {
    vec![
        target_option(),
        model_option(),
        bound_threat_model_option(),
        prompt_option("TAINT_IRIS_NEXT_CATALOG_PROMPT", "catalog generation"),
        opt(
            "maxFiles",
            OptionType::Int,
            "Maximum source files inspected for this draft.",
        )
        .default(json!(512))
        .integer_range(1, 2000)
        .aliases(&["max_files"]),
        opt(
            "maxSourceBytes",
            OptionType::Int,
            "Aggregate source-prefix bytes; shares the inventory's 512 MiB inspection ceiling.",
        )
        .default(json!(4194304))
        .integer_range(1, 16777216)
        .aliases(&["max_source_bytes"]),
        opt(
            "headBytes",
            OptionType::Int,
            "Maximum prefix bytes inspected per source file.",
        )
        .default(json!(4096))
        .integer_range(1, 16384)
        .aliases(&["head_bytes"]),
    ]
}

pub(super) fn read_tool() -> ToolDescriptor {
    tool_with_options("taint-iris-next:catalog-read", "Inspect an exact immutable taint catalog draft and its frozen inputs. Historical reading does not verify current source freshness.",
        vec![target_option(), opt("draftRef", OptionType::String, "Exact draft reference. Omit both references to inspect the active catalog.").aliases(&["draft_ref"]),
            opt("catalogDigestRef", OptionType::String, "Exact immutable saved-catalog digest, independent of the active catalog.").aliases(&["catalog_digest_ref"]),
            opt("section", OptionType::Enum, "Choose the draft summary or frozen inputs actually supplied to the model.")
            .choices(&["summary","inputs"]).default(json!("summary"))])
        .with_policy(read_policy(ToolPhase::Map, WorkspaceRequirement::Required)).without_phase_result()
}

pub(super) fn accept_tool() -> ToolDescriptor {
    let mut policy = workspace_policy(
        ToolPhase::Map,
        RuntimeRequirement::Never,
        FindingStoreRequirement::Optional,
    );
    policy.approval = ApprovalPolicy::Explicit;
    tool_with_options("taint-iris-next:catalog-accept", "Accept one reviewed draft after source and active-catalog checks. Requires explicit approval, starts no scan and cannot complete Map.",
        vec![target_option(), draft_ref(), opt("acknowledgePartial", OptionType::Bool,
            "Explicitly accept the disclosed incomplete source/context after review.").default(json!(false)).aliases(&["acknowledge_partial"]),
            opt("expectedActiveDigest", OptionType::String,
                "After reviewing a changed active catalog, allow replacing exactly this digest without a new model call. Use absent to expect no active catalog.")
                .aliases(&["expected_active_digest"]).advanced()])
        .with_policy(policy).without_phase_result()
}

fn draft_ref() -> OptionSpec {
    opt(
        "draftRef",
        OptionType::String,
        "Exact immutable draft reference from a completed catalog generation job.",
    )
    .required()
    .aliases(&["draft_ref"])
}
