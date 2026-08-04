use super::{context_snapshot_state, journey_model};
use crate::ShellApp;
use kuzushi_core::{Severity, WorkflowPhase};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapabilityDisposition {
    Product,
    Folded,
    Expert,
    Integration,
    Internal,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogModel {
    pub(crate) module_count: usize,
    pub(crate) expanded: bool,
    pub(crate) phase_label: &'static str,
    pub(crate) default_action: Option<CatalogActionModule>,
    pub(crate) collapsed: CatalogCollapsedModel,
    pub(crate) groups: Vec<CatalogModuleGroup>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogActionModule {
    id: String,
    label: String,
    command: String,
    description: String,
    category: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogModuleGroup {
    pub(crate) category: &'static str,
    pub(crate) rows: Vec<CatalogModuleRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogModuleRow {
    pub(crate) id: String,
    pub(crate) command: String,
    pub(crate) cells: [String; 2],
    pub(crate) focused: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogCollapsedModel {
    pub(crate) target_warning: Option<&'static str>,
    pub(crate) next_hint: String,
    pub(crate) scan_hint: Option<String>,
    pub(crate) scan_command: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct CapabilityActionSpec {
    id: &'static str,
    label: &'static str,
    description: &'static str,
    command: &'static str,
    category: &'static str,
    required_tool: Option<&'static str>,
    required_visible_module: Option<&'static str>,
}

impl CapabilityActionSpec {
    fn available(self, app: &ShellApp) -> bool {
        let tool_available = self
            .required_tool
            .is_none_or(|tool| app.registry().resolve_tool(tool).is_some());
        let integration_visible = self.required_visible_module.is_none_or(|id| {
            app.registry()
                .discoverable_modules()
                .any(|module| module.metadata().id == id)
        });
        tool_available && integration_visible
    }

    fn into_action(self) -> CatalogActionModule {
        CatalogActionModule {
            id: self.id.to_string(),
            label: self.label.to_string(),
            command: self.command.to_string(),
            description: self.description.to_string(),
            category: self.category,
        }
    }
}

pub(crate) fn catalog_model(app: &ShellApp) -> CatalogModel {
    debug_assert!(app
        .registry()
        .all_modules()
        .all(|module| capability_disposition(&module.metadata().id).is_some()));
    let phase = journey_model(app)
        .map(|journey| journey.current)
        .unwrap_or(WorkflowPhase::Map);
    let actions = capability_actions(app, phase, app.router.catalog().is_expanded());
    let module_count = actions.len();
    let default_action = actions.first().cloned();
    let cursor_id = selected_cursor_id(app, &actions);
    let focused_id = app.focused_module();
    CatalogModel {
        module_count,
        expanded: app.router.catalog().is_expanded(),
        phase_label: phase_label(phase),
        default_action,
        collapsed: collapsed_catalog_model(app),
        groups: catalog_groups(&actions, focused_id, cursor_id.as_deref()),
    }
}

pub(crate) fn catalog_uses_collapsed_layout(_model: &CatalogModel, _width: u16) -> bool {
    false
}

pub(crate) fn catalog_default_action_hint(module: &CatalogActionModule, width: u16) -> String {
    let prefix = format!("Load {} — ", module.label);
    let budget = (width as usize)
        .saturating_sub(prefix.chars().count() + 4)
        .max(24);
    format!("{prefix}{}", fit_catalog_text(&module.description, budget))
}

pub(crate) fn capability_disposition(id: &str) -> Option<CapabilityDisposition> {
    use CapabilityDisposition::*;
    let disposition = match id {
        "recon" | "threat-model" | "sast" | "findings" | "verify" | "patch" => Product,
        "bounty" | "campaign" | "config" | "context" | "coverage" | "engagement"
        | "entry-points" | "fleet" | "module-recommender" | "pack" | "randori" | "report"
        | "router" | "suppress" | "trace" | "triage" | "workspace" | "worklist" | "x-ray" => Folded,
        "agentic-sast" | "cargo-audit" | "codeql" | "codeql-db" | "cpg" | "dep-hygiene"
        | "fuzz" | "govulncheck" | "iac-scan" | "license-scan" | "ndiff" | "offense-review"
        | "sbom-scan" | "secret-scan" | "semgrep" | "taint-iris-next" | "threat-intel"
        | "variant" => Expert,
        "android-apk" | "prompt-armor" | "shinsa" | "tob" | "vuln-scout" | "wasm-plugin" => {
            Integration
        }
        "classifier-gate" | "context-lite" | "pipeline" | "systems-hunt" => Internal,
        "catalog"
        | "carlini-threat-hunt"
        | "chrome-rce"
        | "deep-audit"
        | "exploit-chain"
        | "full-mode"
        | "offense"
        | "pwn"
        | "taint-iris"
        | "threat-leads"
        | "uaf-hunt"
        | "vendor-assessment" => Retired,
        _ => return None,
    };
    Some(disposition)
}

fn fit_catalog_text(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    if max_chars <= 3 {
        return value.chars().take(max_chars).collect();
    }
    let mut truncated = value
        .chars()
        .take(max_chars.saturating_sub(3))
        .collect::<String>();
    truncated.push_str("...");
    truncated
}

fn collapsed_catalog_model(app: &ShellApp) -> CatalogCollapsedModel {
    CatalogCollapsedModel {
        target_warning: collapsed_target_warning(app),
        next_hint: catalog_next_hint(app),
        scan_hint: app.findings().is_empty().then(|| app.first_finding_hint()),
        scan_command: app.first_finding_scan_command(),
    }
}

fn collapsed_target_warning(app: &ShellApp) -> Option<&'static str> {
    if app.target().is_none() {
        return Some("[!] target required; Enter opens picker · `target <path>` · `demo` offline");
    }
    app.findings()
        .is_empty()
        .then_some("[!] active target has no persisted findings yet")
}

fn catalog_next_hint(app: &ShellApp) -> String {
    match context_snapshot_state(app) {
        "missing" => {
            return "Build the context snapshot with `context build` so SAST has structure to walk."
                .to_string();
        }
        "malformed" => {
            return "Context snapshot is malformed; rerun `context build` before scanning."
                .to_string();
        }
        _ => {}
    }
    critical_finding_hint(app)
        .or_else(|| findings_waiting_hint(app))
        .unwrap_or_else(|| app.first_finding_hint())
}

fn critical_finding_hint(app: &ShellApp) -> Option<String> {
    has_critical_finding(app)
        .then(|| super::findings::cached_sorted_finding_alias_indices(app).into_iter().next())
        .flatten()
        .map(|(alias, _)| {
            format!(
                "Drill in: `open {alias}` for the highest-severity finding · `findings` for the list."
            )
        })
}

fn findings_waiting_hint(app: &ShellApp) -> Option<String> {
    (!app.findings().is_empty()).then(|| {
        let count = app.findings_total_count();
        let loaded = app.findings().len();
        let count_label = if count > loaded {
            format!("{loaded}/{count} findings loaded")
        } else {
            format!(
                "{count} {}",
                if count == 1 { "finding" } else { "findings" }
            )
        };
        format!("{count_label} waiting · `findings` to review · `next` to continue.")
    })
}

fn has_critical_finding(app: &ShellApp) -> bool {
    app.findings()
        .iter()
        .any(|finding| finding.severity == Severity::Critical)
}

fn capability_actions(
    app: &ShellApp,
    phase: WorkflowPhase,
    include_expert: bool,
) -> Vec<CatalogActionModule> {
    let mut specs = default_action_specs(phase).to_vec();
    if include_expert {
        specs.extend_from_slice(expert_action_specs(phase));
        specs.extend_from_slice(integration_action_specs(phase));
    }
    specs
        .into_iter()
        .filter(|spec| spec.available(app))
        .map(CapabilityActionSpec::into_action)
        .collect()
}

fn default_action_specs(phase: WorkflowPhase) -> &'static [CapabilityActionSpec] {
    match phase {
        WorkflowPhase::Map => &MAP_ACTIONS,
        WorkflowPhase::Scan => &SCAN_ACTIONS,
        WorkflowPhase::Review => &REVIEW_ACTIONS,
        WorkflowPhase::Prove => &PROVE_ACTIONS,
        WorkflowPhase::Fix => &FIX_ACTIONS,
    }
}

fn expert_action_specs(phase: WorkflowPhase) -> &'static [CapabilityActionSpec] {
    match phase {
        WorkflowPhase::Map => &MAP_EXPERT_ACTIONS,
        WorkflowPhase::Scan => &SCAN_EXPERT_ACTIONS,
        WorkflowPhase::Review => &REVIEW_EXPERT_ACTIONS,
        WorkflowPhase::Prove => &PROVE_EXPERT_ACTIONS,
        WorkflowPhase::Fix => &FIX_EXPERT_ACTIONS,
    }
}

fn integration_action_specs(phase: WorkflowPhase) -> &'static [CapabilityActionSpec] {
    match phase {
        WorkflowPhase::Scan => &SCAN_INTEGRATION_ACTIONS,
        WorkflowPhase::Fix => &FIX_INTEGRATION_ACTIONS,
        WorkflowPhase::Map | WorkflowPhase::Review | WorkflowPhase::Prove => &[],
    }
}

fn selected_cursor_id(app: &ShellApp, actions: &[CatalogActionModule]) -> Option<String> {
    let visible_ids = ordered_visible_action_ids(actions);
    let cursor = app.router.catalog().cursor();
    visible_ids
        .get(cursor.min(visible_ids.len().saturating_sub(1)))
        .cloned()
}

fn ordered_visible_action_ids(actions: &[CatalogActionModule]) -> Vec<String> {
    catalog_groups(actions, None, None)
        .into_iter()
        .flat_map(|group| group.rows.into_iter().map(|row| row.id))
        .collect()
}

fn catalog_groups(
    actions: &[CatalogActionModule],
    focused_id: Option<&str>,
    cursor_id: Option<&str>,
) -> Vec<CatalogModuleGroup> {
    let mut grouped: BTreeMap<&'static str, Vec<CatalogModuleRow>> = BTreeMap::new();
    for action in actions {
        grouped
            .entry(action.category)
            .or_default()
            .push(action_row(action, focused_id, cursor_id));
    }
    ["CURRENT", "EXPERT", "INTEGRATIONS"]
        .into_iter()
        .filter_map(|category| {
            grouped
                .remove(category)
                .map(|rows| CatalogModuleGroup { category, rows })
        })
        .collect()
}

fn action_row(
    action: &CatalogActionModule,
    focused_id: Option<&str>,
    cursor_id: Option<&str>,
) -> CatalogModuleRow {
    CatalogModuleRow {
        id: action.id.clone(),
        command: action.command.clone(),
        cells: [action.label.clone(), action.description.clone()],
        focused: focused_id == Some(action.id.as_str()) || cursor_id == Some(action.id.as_str()),
    }
}

fn phase_label(phase: WorkflowPhase) -> &'static str {
    match phase {
        WorkflowPhase::Map => "MAP",
        WorkflowPhase::Scan => "SCAN",
        WorkflowPhase::Review => "REVIEW",
        WorkflowPhase::Prove => "PROVE",
        WorkflowPhase::Fix => "FIX",
    }
}

macro_rules! action {
    ($id:literal, $label:literal, $description:literal, $command:literal, $category:literal) => {
        CapabilityActionSpec {
            id: $id,
            label: $label,
            description: $description,
            command: $command,
            category: $category,
            required_tool: None,
            required_visible_module: None,
        }
    };
    ($id:literal, $label:literal, $description:literal, $command:literal, $category:literal, tool = $tool:literal) => {
        CapabilityActionSpec {
            id: $id,
            label: $label,
            description: $description,
            command: $command,
            category: $category,
            required_tool: Some($tool),
            required_visible_module: None,
        }
    };
    ($id:literal, $label:literal, $description:literal, $command:literal, $category:literal, tool = $tool:literal, module = $module:literal) => {
        CapabilityActionSpec {
            id: $id,
            label: $label,
            description: $description,
            command: $command,
            category: $category,
            required_tool: Some($tool),
            required_visible_module: Some($module),
        }
    };
}

const MAP_ACTIONS: [CapabilityActionSpec; 3] = [
    action!(
        "quick-map",
        "Quick map",
        "Build context and entry points",
        "next",
        "CURRENT"
    ),
    action!(
        "deep-map",
        "Deep threat map",
        "Build the DFD and threat model",
        "run threat-model:build",
        "CURRENT",
        tool = "threat-model:build"
    ),
    action!(
        "import-recon",
        "Import recon",
        "Load nmap XML into the engagement",
        "recon:import nmap-xml ",
        "CURRENT",
        tool = "recon:import"
    ),
];

const SCAN_ACTIONS: [CapabilityActionSpec; 3] = [
    action!(
        "recommended-hunt",
        "Recommended hunt",
        "Open the target-aware Scan phase planner",
        "scan",
        "CURRENT",
        tool = "sast:scan"
    ),
    action!(
        "focused-hunt",
        "Focused dataflow hunt",
        "Plan source-to-sink corroboration",
        "run taint-iris-next:dataflow-plan",
        "CURRENT",
        tool = "taint-iris-next:dataflow-plan"
    ),
    action!(
        "supply-chain-hunt",
        "Supply-chain hunt",
        "Inspect dependency and advisory risk",
        "run dep-hygiene:check",
        "CURRENT",
        tool = "dep-hygiene:check"
    ),
];

const REVIEW_ACTIONS: [CapabilityActionSpec; 2] = [
    action!(
        "review-findings",
        "Review next finding",
        "Open the grouped review queue",
        "findings",
        "CURRENT"
    ),
    action!(
        "triage-findings",
        "Triage findings",
        "Classify exploitability and evidence",
        "run triage:run",
        "CURRENT",
        tool = "triage:run"
    ),
];

const PROVE_ACTIONS: [CapabilityActionSpec; 1] = [action!(
    "verify-finding",
    "Verify exploitability",
    "Add a finding reference before submitting",
    "run verify:finding ",
    "CURRENT",
    tool = "verify:finding"
)];

const FIX_ACTIONS: [CapabilityActionSpec; 3] = [
    action!(
        "generate-patch",
        "Generate patch",
        "Draft a fix for the selected finding",
        "run patch:finding ",
        "CURRENT",
        tool = "patch:finding"
    ),
    action!(
        "review-patch",
        "Review patch",
        "Apply or reject the prepared patch",
        "patch apply",
        "CURRENT"
    ),
    action!(
        "export-findings",
        "Export findings",
        "Write a SARIF report for handoff",
        "findings export report.sarif sarif",
        "CURRENT",
        tool = "workspace:export-findings"
    ),
];

const MAP_EXPERT_ACTIONS: [CapabilityActionSpec; 7] = [
    action!(
        "context",
        "Repository context",
        "Build the shared context snapshot",
        "run context:build",
        "EXPERT",
        tool = "context:build"
    ),
    action!(
        "entry-points",
        "Entry points",
        "Extract the attack-surface routes",
        "run entry-points:extract",
        "EXPERT",
        tool = "entry-points:extract"
    ),
    action!(
        "x-ray",
        "Architecture X-ray",
        "Deep-map architecture and trust boundaries",
        "run x-ray:run",
        "EXPERT",
        tool = "x-ray:run"
    ),
    action!(
        "cpg",
        "Code property graph",
        "Build the in-process cpg-rs graphs",
        "run cpg:build",
        "EXPERT",
        tool = "cpg:build"
    ),
    action!(
        "codeql-db",
        "CodeQL database",
        "Build the semantic query database",
        "run codeql:create-db",
        "EXPERT",
        tool = "codeql:create-db"
    ),
    action!(
        "threat-intel",
        "Threat intelligence",
        "Discover target-relevant CVE candidates",
        "run threat-intel:discover",
        "EXPERT",
        tool = "threat-intel:discover"
    ),
    action!(
        "ndiff",
        "N-day diff",
        "Fetch and inspect a known vulnerability fix",
        "run ndiff:fetch-cve",
        "EXPERT",
        tool = "ndiff:fetch-cve"
    ),
];

const SCAN_EXPERT_ACTIONS: [CapabilityActionSpec; 16] = [
    action!(
        "semgrep",
        "Semgrep",
        "Fast structural source scan",
        "run semgrep:scan",
        "EXPERT",
        tool = "semgrep:scan"
    ),
    action!(
        "codeql",
        "CodeQL",
        "Semantic taint-query scan",
        "run codeql:scan",
        "EXPERT",
        tool = "codeql:scan"
    ),
    action!(
        "agentic-sast",
        "Agentic SAST",
        "Model-backed intent and flow review",
        "run agentic-sast:scan",
        "EXPERT",
        tool = "agentic-sast:scan"
    ),
    action!(
        "offense-review",
        "Threat-model hunt",
        "Adversarial review against mapped threats",
        "run offense-review:threat-hunt",
        "EXPERT",
        tool = "offense-review:threat-hunt"
    ),
    action!(
        "taint-iris-next",
        "Taint IRIS",
        "Advanced source-to-sink evidence",
        "run taint-iris-next:dataflow-plan",
        "EXPERT",
        tool = "taint-iris-next:dataflow-plan"
    ),
    action!(
        "secret-scan",
        "Secret scan",
        "Find committed credentials and tokens",
        "run secret-scan:scan",
        "EXPERT",
        tool = "secret-scan:scan"
    ),
    action!(
        "iac-scan",
        "IaC scan",
        "Inspect infrastructure configuration",
        "run iac-scan:scan",
        "EXPERT",
        tool = "iac-scan:scan"
    ),
    action!(
        "cargo-audit",
        "Cargo audit",
        "Check Rust advisory exposure",
        "run cargo-audit:scan",
        "EXPERT",
        tool = "cargo-audit:scan"
    ),
    action!(
        "govulncheck",
        "Govulncheck",
        "Check reachable Go vulnerabilities",
        "run govulncheck:scan",
        "EXPERT",
        tool = "govulncheck:scan"
    ),
    action!(
        "dep-hygiene",
        "Dependency hygiene",
        "Inspect stale and policy-risky packages",
        "run dep-hygiene:check",
        "EXPERT",
        tool = "dep-hygiene:check"
    ),
    action!(
        "license-scan",
        "License scan",
        "Inspect dependency license policy",
        "run license-scan:scan",
        "EXPERT",
        tool = "license-scan:scan"
    ),
    action!(
        "sbom-scan",
        "SBOM",
        "Build the supply-chain inventory",
        "run sbom-scan:scan",
        "EXPERT",
        tool = "sbom-scan:scan"
    ),
    action!(
        "variant",
        "Variant hunt",
        "Search siblings of a confirmed pattern",
        "run variant:hunt",
        "EXPERT",
        tool = "variant:hunt"
    ),
    action!(
        "fuzz-run",
        "Coverage fuzzing",
        "Run bounded AFE campaign rounds (C/C++)",
        "run fuzz:run",
        "EXPERT",
        tool = "fuzz:run"
    ),
    action!(
        "fuzz-sweep",
        "MSan corpus sweep",
        "Replay corpora under a sanitizer variant",
        "run fuzz:sweep",
        "EXPERT",
        tool = "fuzz:sweep"
    ),
    action!(
        "fuzz-differential",
        "Differential replay",
        "Fork-vs-upstream divergence oracle",
        "run fuzz:differential",
        "EXPERT",
        tool = "fuzz:differential"
    ),
];

const REVIEW_EXPERT_ACTIONS: [CapabilityActionSpec; 1] = [action!(
    "triage",
    "Deep triage",
    "Run the canonical evidence classifier",
    "run triage:run",
    "EXPERT",
    tool = "triage:run"
)];

const PROVE_EXPERT_ACTIONS: [CapabilityActionSpec; 1] = [action!(
    "verify",
    "Empirical verify",
    "Run proof against a finding reference",
    "run verify:finding ",
    "EXPERT",
    tool = "verify:finding"
)];

const FIX_EXPERT_ACTIONS: [CapabilityActionSpec; 3] = [
    action!(
        "patch",
        "Patch finding",
        "Generate a reviewed remediation diff",
        "run patch:finding ",
        "EXPERT",
        tool = "patch:finding"
    ),
    action!(
        "report",
        "Build report",
        "Render the evidence-backed report",
        "run report:build",
        "EXPERT",
        tool = "report:build"
    ),
    action!(
        "workspace-export",
        "Workspace export",
        "Export the findings ledger",
        "run workspace:export-findings",
        "EXPERT",
        tool = "workspace:export-findings"
    ),
];

const SCAN_INTEGRATION_ACTIONS: [CapabilityActionSpec; 5] = [
    action!(
        "android-apk",
        "Android APK",
        "Analyze a decompiled Android target",
        "run android-apk:scan",
        "INTEGRATIONS",
        tool = "android-apk:scan",
        module = "android-apk"
    ),
    action!(
        "prompt-armor",
        "PromptArmor",
        "Audit prompt-injection surfaces",
        "run prompt-armor:scan",
        "INTEGRATIONS",
        tool = "prompt-armor:scan",
        module = "prompt-armor"
    ),
    action!(
        "tob",
        "Trail of Bits",
        "Run the optional skills audit",
        "run tob:audit",
        "INTEGRATIONS",
        tool = "tob:audit",
        module = "tob"
    ),
    action!(
        "vuln-scout",
        "Vuln Scout",
        "Run the optional whitebox audit",
        "run vuln-scout:audit",
        "INTEGRATIONS",
        tool = "vuln-scout:audit",
        module = "vuln-scout"
    ),
    action!(
        "wasm-plugin",
        "Wasm analyzer",
        "Run a loaded Wasm analyzer",
        "run wasm-plugin:analyze",
        "INTEGRATIONS",
        tool = "wasm-plugin:analyze",
        module = "wasm-plugin"
    ),
];

const FIX_INTEGRATION_ACTIONS: [CapabilityActionSpec; 1] = [action!(
    "shinsa",
    "Shinsa compliance",
    "Run an installed compliance framework",
    "run shinsa:scan",
    "INTEGRATIONS",
    tool = "shinsa:scan",
    module = "shinsa"
)];

#[cfg(test)]
mod tests;
