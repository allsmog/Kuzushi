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
        nmap_tool().with_policy(external_action_policy(ToolPhase::Map, RuntimeRequirement::Never, FindingStoreRequirement::Optional)),
        subdomain_tool().with_policy(external_action_policy(ToolPhase::Map, RuntimeRequirement::Never, FindingStoreRequirement::Optional)),
        http_fingerprint_tool().with_policy(external_action_policy(ToolPhase::Map, RuntimeRequirement::Never, FindingStoreRequirement::Optional)),
        // Importing candidate findings is Scan truth even though the source is
        // reconnaissance data; the resulting attempt must precede Review.
        recon_import_tool().with_policy(workspace_policy(ToolPhase::Scan, RuntimeRequirement::Never, FindingStoreRequirement::Optional)),
    ]
}

fn nmap_tool() -> ToolDescriptor {
    tool_with_options(
        "recon:nmap",
        "Run nmap reconnaissance.",
        vec![
            opt("target", OptionType::String, "Host or network target.").required(),
            opt(
                "ports",
                OptionType::String,
                "Port set or comma-separated port list.",
            )
            .default(json!("top100")),
            binary_option("nmap binary path."),
        ],
    )
}

fn subdomain_tool() -> ToolDescriptor {
    tool_with_options(
        "recon:subdomain",
        "Run subdomain reconnaissance.",
        vec![
            opt("domain", OptionType::String, "Domain to enumerate.").required(),
            opt("source", OptionType::Enum, "Subdomain source.")
                .choices(&["crtsh", "wayback", "both"])
                .default(json!("both")),
            timeout_seconds_option(20),
            binary_option("curl binary path."),
        ],
    )
}

fn http_fingerprint_tool() -> ToolDescriptor {
    tool_with_options(
        "recon:http-fingerprint",
        "Fingerprint HTTP services and technology stacks.",
        vec![
            opt("target", OptionType::String, "HTTP service URL or host.").required(),
            timeout_seconds_option(10),
            binary_option("curl binary path."),
        ],
    )
}

fn recon_import_tool() -> ToolDescriptor {
    tool_with_options(
        "recon:import",
        "Import recon and HTTP evidence (amass, httpx, nuclei, nmap-xml, Burp XML, HAR).",
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
        "HTTP fetch timeout in seconds.",
    )
    .aliases(&["timeout_seconds"])
    .default(json!(default))
}
