use super::*;

pub(crate) fn threat_intel_module() -> BuiltinModule {
    builtin_module(
        "threat-intel",
        "Threat Intelligence Catalog",
        ModuleKind::Intel,
        "Per-target detector catalog seeded from a project's CVE history. Each entry \
         describes the source/sink/sanitizer pattern of one historical CVE and dispatches \
         to the right native hunt (uaf-hunt, taint-iris-next, systems-hunt, variant).",
        vec![
            tool_with_options(
                "threat-intel:list",
                "List the entries declared in a threat-intel catalog TOML.",
                vec![
                    opt(
                        "catalogPath",
                        OptionType::Path,
                        "Path to the catalog TOML. Defaults to the first .toml under <target>/.kuzushi/catalogs/.",
                    ),
                ],
            ),
            tool_with_options(
                "threat-intel:apply",
                "Plan or dispatch the catalog: route each entry to its hunt module. \
                 Defaults to dryRun=true.",
                vec![
                    opt(
                        "catalogPath",
                        OptionType::Path,
                        "Path to the catalog TOML. Defaults to the first .toml under <target>/.kuzushi/catalogs/.",
                    ),
                    opt(
                        "dryRun",
                        OptionType::Bool,
                        "When true (default), produce the dispatch plan without invoking the underlying hunts. Set false to actually spend agent budget.",
                    )
                    .default(json!(true)),
                ],
            ),
            tool_with_options(
                "threat-intel:harvest",
                "Build a catalog TOML from a list of CVE IDs. For each CVE, calls \
                 ndiff:fetch-cve + ndiff:extract-fix-pattern, then writes one entry per \
                 CVE to the output catalog. The `cves` field is the only JSON-only input \
                 (array of strings).",
                vec![
                    opt(
                        "cves",
                        OptionType::Json,
                        "Array of CVE IDs to harvest into catalog entries.",
                    )
                    .required(),
                    opt(
                        "outputPath",
                        OptionType::Path,
                        "Destination catalog TOML. Defaults to <target>/.kuzushi/catalogs/harvested.toml. Existing files are appended to.",
                    ),
                    model_option(),
                ],
            ),
        ],
        vec![],
    )
}
