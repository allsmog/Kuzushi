use super::*;

pub(crate) fn pack_module() -> BuiltinModule {
    builtin_module(
        "pack",
        "Knowledge Packs",
        ModuleKind::Intel,
        "Validate out-of-tree knowledge packs before installing them into a workspace.",
        vec![
            pack_lint_tool().with_policy(read_policy(
                ToolPhase::Map,
                WorkspaceRequirement::Optional,
            )),
            suggest_shards_tool().with_policy(workspace_policy(
                ToolPhase::Map,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Optional,
            )),
        ],
        vec![],
    )
}

fn suggest_shards_tool() -> ToolDescriptor {
    tool_with_options(
        "pack:suggest-shards",
        "Propose at most eight shard candidates from one bounded repository \
         inventory (file counts, language mix, and extracted entry points). \
         Keeps parent files covered and discloses incomplete inventory. Writes \
         a commented DRAFT shards.toml under the workspace state dir for an \
         operator to edit — never installs it. No model calls.",
        vec![
            opt(
                "output",
                OptionType::Path,
                "Draft output path. Relative paths resolve under the target \
                 root; default .kuzushi/v3/reports/suggested-shards.toml.",
            )
            .aliases(&["out"])
            .target_write(),
            opt(
                "emitScopes",
                OptionType::Bool,
                "Also materialize the shard candidates as the nested \
                 project-scope tree (.kuzushi/project-model/scopes.json) so \
                 planners and threat modeling see the decomposition. The \
                 shards.toml draft stays a never-auto-installed review copy.",
            )
            .aliases(&["emit_scopes"])
            .default(json!(false)),
        ],
    )
}

fn pack_lint_tool() -> ToolDescriptor {
    tool_with_options(
        "pack:lint",
        "Deterministically lint a knowledge pack: pack.toml shape, shard \
         manifests (path existence and scope size when a target is active), \
         threat-model schema (severity values, CWE well-formedness, threats \
         present for planning), and prompt fragment destinations. The result \
         fails when any ERROR row exists, so `kuzushi run pack:lint` exits \
         nonzero in CI. No model calls.",
        vec![
            opt(
                "packDir",
                OptionType::Path,
                "Pack root directory containing pack.toml.",
            )
            .aliases(&["pack_dir", "pack"])
            .external_read()
            .required(),
            opt(
                "product",
                OptionType::String,
                "Lint only this [products.<name>] block. Default: all products.",
            ),
        ],
    )
}
