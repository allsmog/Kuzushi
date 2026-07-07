use crate::ShellApp;
use kuzushi_core::modules::{BuiltinModule, ModuleKind, ModuleMetadata, ToolDescriptor};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolsModel {
    pub(crate) groups: Vec<ToolGroup>,
    pub(crate) visible_count: usize,
    pub(crate) total_count: usize,
    pub(crate) filter: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolGroup {
    pub(crate) label: &'static str,
    pub(crate) hint: &'static str,
    pub(crate) rows: Vec<ToolRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolRow {
    pub(crate) cells: [String; 3],
}

pub(crate) fn tools_model(app: &ShellApp) -> ToolsModel {
    let filter = normalized_filter(app.router.tools().filter());
    let modules = app.registry.modules().collect::<Vec<_>>();
    let groups = tool_groups(&modules, filter.as_ref());
    let visible_count = groups.iter().map(|group| group.rows.len()).sum();
    ToolsModel {
        groups,
        visible_count,
        total_count: modules
            .iter()
            .map(|module| visible_tool_count(module))
            .sum(),
        filter: app.router.tools().filter_clone(),
    }
}

fn normalized_filter(raw: Option<&str>) -> Option<Vec<String>> {
    let tokens = raw?
        .split_whitespace()
        .map(|token| token.to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    (!tokens.is_empty()).then_some(tokens)
}

fn tool_matches_filter(name: &str, description: &str, tokens: &[String]) -> bool {
    let haystack = format!("{name} {description}").to_ascii_lowercase();
    tokens.iter().all(|token| haystack.contains(token))
}

fn tool_groups(modules: &[&BuiltinModule], filter: Option<&Vec<String>>) -> Vec<ToolGroup> {
    TOOL_GROUPS
        .iter()
        .filter_map(|group| tool_group(modules, filter, group))
        .collect()
}

fn tool_group(
    modules: &[&BuiltinModule],
    filter: Option<&Vec<String>>,
    group: &ToolGroupSpec,
) -> Option<ToolGroup> {
    let rows = modules
        .iter()
        .flat_map(|module| module_tool_rows(module, filter, group.key))
        .collect::<Vec<_>>();
    (!rows.is_empty()).then_some(ToolGroup {
        label: group.label,
        hint: group.hint,
        rows,
    })
}

fn module_tool_rows(
    module: &BuiltinModule,
    filter: Option<&Vec<String>>,
    group: &'static str,
) -> Vec<ToolRow> {
    let metadata = module.metadata();
    module
        .tools()
        .iter()
        .filter(|tool| !tool.hidden)
        .filter(|tool| tool_group_key(metadata, tool) == group)
        .filter(|tool| tool_filter_matches(metadata, tool, filter))
        .map(tool_row)
        .collect()
}

fn tool_filter_matches(
    metadata: &ModuleMetadata,
    tool: &ToolDescriptor,
    filter: Option<&Vec<String>>,
) -> bool {
    filter.as_ref().map_or(true, |tokens| {
        let description = format!(
            "{} {} {}",
            metadata.id, metadata.description, tool.description
        );
        tool_matches_filter(tool.name.as_str(), &description, tokens)
    })
}

fn tool_row(tool: &ToolDescriptor) -> ToolRow {
    ToolRow {
        cells: [
            tool.name.clone(),
            concise_tool_description(&tool.description),
            tool_next_command(tool),
        ],
    }
}

fn visible_tool_count(module: &BuiltinModule) -> usize {
    module.tools().iter().filter(|tool| !tool.hidden).count()
}

fn concise_tool_description(description: &str) -> String {
    description
        .split('.')
        .next()
        .unwrap_or(description)
        .trim()
        .to_string()
}

fn tool_next_command(tool: &ToolDescriptor) -> String {
    if tool.options.is_empty() {
        format!("run {}", tool.name)
    } else {
        format!("options {}", tool.name)
    }
}

fn tool_group_key(metadata: &ModuleMetadata, tool: &ToolDescriptor) -> &'static str {
    match metadata.id.as_str() {
        "context" | "context-lite" | "recon" | "threat-model" | "workspace" | "x-ray"
        | "entry-points" | "cpg" | "codeql-db" | "threat-intel" | "randori" | "ndiff" => "map",
        "sast"
        | "semgrep"
        | "codeql"
        | "agentic-sast"
        | "taint-iris"
        | "taint-iris-next"
        | "secret-scan"
        | "iac-scan"
        | "cargo-audit"
        | "govulncheck"
        | "dep-hygiene"
        | "android-apk"
        | "chrome-rce"
        | "carlini-threat-hunt"
        | "uaf-hunt"
        | "exploit-chain"
        | "systems-hunt" => "hunt",
        "findings" | "triage" | "verify" | "classifier-gate" | "deep-audit" | "threat-leads" => {
            "confirm"
        }
        "patch" | "report" => "fix",
        _ => fallback_tool_group(metadata.kind, &tool.name),
    }
}

fn fallback_tool_group(kind: ModuleKind, tool_name: &str) -> &'static str {
    if tool_name.contains("patch") || tool_name.contains("report") {
        return "fix";
    }
    match kind {
        ModuleKind::Offense | ModuleKind::Scan | ModuleKind::Defense => "hunt",
        ModuleKind::Intel | ModuleKind::Context | ModuleKind::Workspace => "map",
        ModuleKind::Findings | ModuleKind::Triage => "confirm",
        ModuleKind::Governance
        | ModuleKind::Config
        | ModuleKind::Catalog
        | ModuleKind::Internal => "operate",
    }
}

struct ToolGroupSpec {
    key: &'static str,
    label: &'static str,
    hint: &'static str,
}

const TOOL_GROUPS: &[ToolGroupSpec] = &[
    ToolGroupSpec {
        key: "map",
        label: "MAP",
        hint: "build context, scope, inventory, and threat model",
    },
    ToolGroupSpec {
        key: "hunt",
        label: "HUNT",
        hint: "find candidate vulnerabilities and security signals",
    },
    ToolGroupSpec {
        key: "confirm",
        label: "CONFIRM",
        hint: "rank, triage, verify, and inspect findings",
    },
    ToolGroupSpec {
        key: "fix",
        label: "FIX",
        hint: "patch findings and produce reports",
    },
    ToolGroupSpec {
        key: "operate",
        label: "OPERATE",
        hint: "configure providers, models, catalogs, and policy",
    },
];

#[cfg(test)]
mod tests;
