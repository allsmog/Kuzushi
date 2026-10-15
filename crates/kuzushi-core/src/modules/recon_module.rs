use super::*;

pub(crate) fn recon_module() -> BuiltinModule {
    builtin_module(
        "recon",
        "Recon",
        ModuleKind::Intel,
        "Network and web reconnaissance tools.",
        recon_tools(),
        vec![dag("recon:http-fingerprint", "context", &["context:build"])],
    )
}

fn recon_tools() -> Vec<ToolDescriptor> {
    vec![
        nmap_tool().with_policy(external_action_policy(
            ToolPhase::Map,
            RuntimeRequirement::Never,
            FindingStoreRequirement::Optional,
        )),
        subdomain_tool().with_policy(external_action_policy(
            ToolPhase::Map,
            RuntimeRequirement::Never,
            FindingStoreRequirement::Optional,
        )),
        http_fingerprint_tool().with_policy(external_action_policy(
            ToolPhase::Map,
            RuntimeRequirement::Never,
            FindingStoreRequirement::Optional,
        )),
        recon_import_tool()
            .with_policy(workspace_policy(
                ToolPhase::Scan,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Optional,
            ))
            .without_phase_result(),
    ]
}

fn nmap_tool() -> ToolDescriptor {
    tool_with_options(
        "recon:nmap",
        "Experimental external host/service observations with explicit consent and a process deadline. Live probing, broad network scope and source accuracy remain unqualified; this action does not complete repository Map.",
        vec![
            opt("target", OptionType::String, "Host or network target.").required(),
            opt(
                "ports",
                OptionType::String,
                "top100, top1000, or an ascending numeric port/range list from 1 to 65535; maximum 4096 bytes.",
            )
            .default(json!("top100")),
            binary_option("nmap binary path."),
            timeout_seconds_option(60),
        ],
    )
    .with_discovery_maturity(ModuleMaturity::Labs)
    .without_phase_result()
}

fn subdomain_tool() -> ToolDescriptor {
    tool_with_options(
        "recon:subdomain",
        "Experimental historical names from certificate/archive metadata. Names do not establish liveness or repository coverage. External consent required; no Map completion.",
        vec![
            opt("domain", OptionType::String, "Domain to enumerate.").required(),
            opt("source", OptionType::Enum, "Subdomain source.")
                .choices(&["crtsh", "wayback", "both"])
                .default(json!("both")),
            timeout_seconds_option(20),
            binary_option("curl binary path."),
        ],
    )
    .with_discovery_maturity(ModuleMaturity::Labs)
    .without_phase_result()
}

fn http_fingerprint_tool() -> ToolDescriptor {
    tool_with_options(
        "recon:http-fingerprint",
        "Experimental HTTP endpoint observations with explicit consent and bounded redirects. Reported technologies, live probing and repository coverage remain unqualified; no Map completion.",
        vec![
            opt("target", OptionType::String, "HTTP service URL or host.").required(),
            timeout_seconds_option(10),
            binary_option("curl binary path."),
        ],
    )
    .with_discovery_maturity(ModuleMaturity::Labs)
    .without_phase_result()
}

fn recon_import_tool() -> ToolDescriptor {
    tool_with_options(
        "recon:import",
        "Import recorded recon and HTTP evidence for inspection (amass, httpx, nuclei, nmap-xml, Burp XML, HAR). Does not establish local scan coverage.",
        vec![
            opt("tool", OptionType::Enum, "Recon export format to import.")
                .choices(&["amass", "httpx", "nuclei", "nmap-xml", "burp-xml", "har"])
                .aliases(&["source", "format"])
                .required(),
            opt("path", OptionType::Path, "Path to the recon export file.")
                .external_read()
                .required(),
        ],
    )
}

fn timeout_seconds_option(default: u64) -> OptionSpec {
    opt(
        "timeoutSeconds",
        OptionType::Int,
        "Per-process wall-clock and transport timeout, from 1 to 300 seconds. A multi-source or redirect action can run more than one bounded process.",
    )
    .aliases(&["timeout_seconds"])
    .default(json!(default))
    .integer_range(1,300)
}
