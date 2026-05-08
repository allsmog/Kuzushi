use super::*;

pub(crate) fn recon_module() -> BuiltinModule {
    builtin_module(
        "recon",
        "Recon",
        ModuleKind::Intel,
        "Network and web reconnaissance tools.",
        vec![
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
            ),
            tool_with_options(
                "recon:subdomain",
                "Run subdomain reconnaissance.",
                vec![
                    opt("domain", OptionType::String, "Domain to enumerate.").required(),
                    opt("source", OptionType::Enum, "Subdomain source.")
                        .choices(&["crtsh", "wayback", "both"])
                        .default(json!("both")),
                    opt(
                        "timeoutSeconds",
                        OptionType::Int,
                        "HTTP fetch timeout in seconds.",
                    )
                    .default(json!(20)),
                    binary_option("curl binary path."),
                ],
            ),
            tool_with_options(
                "recon:http-fingerprint",
                "Fingerprint HTTP services and technology stacks.",
                vec![
                    opt("target", OptionType::String, "HTTP service URL or host.").required(),
                    opt(
                        "timeoutSeconds",
                        OptionType::Int,
                        "HTTP fetch timeout in seconds.",
                    )
                    .default(json!(10)),
                    binary_option("curl binary path."),
                ],
            ),
        ],
        vec![dag("recon:http-fingerprint", "context", &["context:build"])],
    )
}
