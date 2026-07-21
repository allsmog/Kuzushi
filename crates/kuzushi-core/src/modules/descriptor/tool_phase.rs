use super::ModuleKind;
use serde::{Deserialize, Serialize};

/// Canonical journey phase a tool belongs to. This is the single source of
/// truth that the CLI (`tools --json`), the shell Tools/Catalog views, and the
/// `ToolQuery` grammar all read — replacing the previously triplicated
/// phase/category tables that lived only in the TUI.
///
/// This metadata drives catalog grouping and the shared autonomy ceiling at
/// dispatch. It is not DAG execution-ordering input: declaring a phase never
/// schedules dependencies or changes executor order by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ToolPhase {
    /// Build context, scope, inventory, and threat model.
    Map,
    /// Find candidate vulnerabilities and security signals.
    #[serde(alias = "hunt")]
    Scan,
    /// Triage, classify, and record decisions about candidate findings.
    Review,
    /// Verify actionable findings with empirical evidence.
    #[serde(alias = "confirm")]
    Prove,
    /// Patch findings and produce reports.
    Fix,
    /// Configure providers, models, catalogs, and policy — also the honest
    /// "expert/other" bucket for tools (including dynamic/SDK modules) that
    /// declare no phase.
    #[default]
    Operate,
}

impl ToolPhase {
    /// Canonical group order shared by every phase-grouped surface.
    pub const ORDER: [ToolPhase; 6] = [
        ToolPhase::Map,
        ToolPhase::Scan,
        ToolPhase::Review,
        ToolPhase::Prove,
        ToolPhase::Fix,
        ToolPhase::Operate,
    ];

    /// Uppercase group label (`MAP` … `OPERATE`).
    pub fn label(self) -> &'static str {
        match self {
            ToolPhase::Map => "MAP",
            ToolPhase::Scan => "SCAN",
            ToolPhase::Review => "REVIEW",
            ToolPhase::Prove => "PROVE",
            ToolPhase::Fix => "FIX",
            ToolPhase::Operate => "OPERATE",
        }
    }

    /// Judo glyph for the phase, `None` for the OPERATE/expert bucket.
    pub fn kanji(self) -> Option<&'static str> {
        match self {
            ToolPhase::Map => Some("組"),
            ToolPhase::Scan => Some("崩"),
            ToolPhase::Review => Some("査"),
            ToolPhase::Prove => Some("作"),
            ToolPhase::Fix => Some("掛"),
            ToolPhase::Operate => None,
        }
    }

    /// One-line statement of what the phase is for.
    pub fn hint(self) -> &'static str {
        match self {
            ToolPhase::Map => "build context, scope, inventory, and threat model",
            ToolPhase::Scan => "find candidate vulnerabilities and security signals",
            ToolPhase::Review => "triage, classify, and decide candidate findings",
            ToolPhase::Prove => "verify actionable findings with empirical evidence",
            ToolPhase::Fix => "patch findings and produce reports",
            ToolPhase::Operate => "configure providers, models, catalogs, and policy",
        }
    }

    /// Lowercase machine token (`map` … `operate`) for query grammar output.
    pub fn as_str(self) -> &'static str {
        match self {
            ToolPhase::Map => "map",
            ToolPhase::Scan => "scan",
            ToolPhase::Review => "review",
            ToolPhase::Prove => "prove",
            ToolPhase::Fix => "fix",
            ToolPhase::Operate => "operate",
        }
    }

    /// Parse a named phase. Legacy `hunt` and `confirm` tokens remain aliases;
    /// numbers are rejected because their meaning changed with the new phase.
    pub fn parse(input: &str) -> Option<ToolPhase> {
        match input.trim().to_ascii_lowercase().as_str() {
            "map" | "kumi" | "kumi-kata" | "組" => Some(ToolPhase::Map),
            "scan" | "hunt" | "kuzushi" | "崩" => Some(ToolPhase::Scan),
            "review" => Some(ToolPhase::Review),
            "prove" | "confirm" | "verify" | "tsukuri" | "作" => Some(ToolPhase::Prove),
            "fix" | "kake" | "掛" => Some(ToolPhase::Fix),
            "operate" | "expert" | "other" => Some(ToolPhase::Operate),
            _ => None,
        }
    }
}

/// Compatibility mapping for callers that need to classify an unregistered
/// tool. Built-ins declare phase beside each descriptor and registration does
/// not consult this helper.
pub fn canonical_tool_phase(module_id: &str, kind: ModuleKind, tool_name: &str) -> ToolPhase {
    // Per-tool overrides for modules that legitimately span phases: a database
    // build is Map even though the module's scan is Scan, and binary reversing
    // is a Map-phase prep step. Keeps the descriptor phase consistent with the
    // curated planning-task list.
    if let Some(phase) = tool_phase_override(tool_name) {
        return phase;
    }
    match module_id {
        "context" | "context-lite" | "module-recommender" | "recon" | "threat-model"
        | "workspace" | "x-ray" | "entry-points" | "cpg" | "codeql-db" | "threat-intel"
        | "randori" | "ndiff" => ToolPhase::Map,
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
        | "systems-hunt"
        | "sbom-scan"
        | "shinsa"
        | "fuzz"
        | "vendor-assessment"
        | "pipeline" => ToolPhase::Scan,
        "findings" | "triage" | "classifier-gate" | "deep-audit" | "threat-leads" => {
            ToolPhase::Review
        }
        "verify" => ToolPhase::Prove,
        "patch" | "report" => ToolPhase::Fix,
        _ => fallback_tool_phase(kind, tool_name),
    }
}

fn tool_phase_override(tool_name: &str) -> Option<ToolPhase> {
    match tool_name {
        "codeql:create-db" | "pwn:reverse" | "fuzz:author" => Some(ToolPhase::Map),
        "recon:import" | "bounty:import-har" | "bounty:import-burp" => Some(ToolPhase::Scan),
        _ => None,
    }
}

fn fallback_tool_phase(kind: ModuleKind, tool_name: &str) -> ToolPhase {
    if tool_name.contains("patch") || tool_name.contains("report") {
        return ToolPhase::Fix;
    }
    match kind {
        ModuleKind::Offense | ModuleKind::Scan | ModuleKind::Defense => ToolPhase::Scan,
        ModuleKind::Intel | ModuleKind::Context | ModuleKind::Workspace => ToolPhase::Map,
        ModuleKind::Findings | ModuleKind::Triage => ToolPhase::Review,
        ModuleKind::Governance
        | ModuleKind::Config
        | ModuleKind::Catalog
        | ModuleKind::Internal => ToolPhase::Operate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_is_stable_and_labelled() {
        assert_eq!(ToolPhase::ORDER.len(), 6);
        assert_eq!(ToolPhase::Map.label(), "MAP");
        assert_eq!(ToolPhase::Operate.label(), "OPERATE");
        assert_eq!(ToolPhase::Scan.kanji(), Some("崩"));
        assert_eq!(ToolPhase::Operate.kanji(), None);
    }

    #[test]
    fn default_is_operate() {
        assert_eq!(ToolPhase::default(), ToolPhase::Operate);
    }

    #[test]
    fn parse_accepts_word_romaji_and_kanji() {
        assert_eq!(ToolPhase::parse("hunt"), Some(ToolPhase::Scan));
        assert_eq!(ToolPhase::parse("KUZUSHI"), Some(ToolPhase::Scan));
        assert_eq!(ToolPhase::parse("崩"), Some(ToolPhase::Scan));
        assert_eq!(ToolPhase::parse("review"), Some(ToolPhase::Review));
        assert_eq!(ToolPhase::parse("confirm"), Some(ToolPhase::Prove));
        assert_eq!(ToolPhase::parse("2"), None);
        assert_eq!(ToolPhase::parse("operate"), Some(ToolPhase::Operate));
        assert_eq!(ToolPhase::parse("nope"), None);
    }

    #[test]
    fn serde_normalizes_legacy_phase_aliases() {
        assert_eq!(
            serde_json::from_str::<ToolPhase>("\"hunt\"").unwrap(),
            ToolPhase::Scan
        );
        assert_eq!(
            serde_json::from_str::<ToolPhase>("\"confirm\"").unwrap(),
            ToolPhase::Prove
        );
        assert_eq!(serde_json::to_string(&ToolPhase::Scan).unwrap(), "\"scan\"");
        assert_eq!(
            serde_json::to_string(&ToolPhase::Review).unwrap(),
            "\"review\""
        );
        assert_eq!(
            serde_json::to_string(&ToolPhase::Prove).unwrap(),
            "\"prove\""
        );
    }

    #[test]
    fn canonical_phase_matches_curated_modules() {
        assert_eq!(
            canonical_tool_phase("semgrep", ModuleKind::Scan, "semgrep:scan"),
            ToolPhase::Scan
        );
        assert_eq!(
            canonical_tool_phase("threat-model", ModuleKind::Intel, "threat-model:build"),
            ToolPhase::Map
        );
        assert_eq!(
            canonical_tool_phase("triage", ModuleKind::Triage, "triage:run"),
            ToolPhase::Review
        );
        assert_eq!(
            canonical_tool_phase(
                "classifier-gate",
                ModuleKind::Triage,
                "classifier-gate:score"
            ),
            ToolPhase::Review
        );
        assert_eq!(
            canonical_tool_phase("deep-audit", ModuleKind::Triage, "deep-audit:run"),
            ToolPhase::Review
        );
        assert_eq!(
            canonical_tool_phase("verify", ModuleKind::Offense, "verify:finding"),
            ToolPhase::Prove
        );
        assert_eq!(
            canonical_tool_phase("patch", ModuleKind::Offense, "patch:finding"),
            ToolPhase::Fix
        );
    }

    #[test]
    fn finding_imports_are_scan_truth_even_for_context_modules() {
        assert_eq!(
            canonical_tool_phase("recon", ModuleKind::Intel, "recon:import"),
            ToolPhase::Scan
        );
        assert_eq!(
            canonical_tool_phase("bounty", ModuleKind::Intel, "bounty:import-har"),
            ToolPhase::Scan
        );
        assert_eq!(
            canonical_tool_phase("bounty", ModuleKind::Intel, "bounty:import-burp"),
            ToolPhase::Scan
        );
    }

    #[test]
    fn fallback_uses_kind_then_name() {
        // Unknown module id falls back to kind.
        assert_eq!(
            canonical_tool_phase("mystery", ModuleKind::Intel, "mystery:map"),
            ToolPhase::Map
        );
        assert_eq!(
            canonical_tool_phase("mystery", ModuleKind::Config, "mystery:tune"),
            ToolPhase::Operate
        );
        // A patch/report tool name overrides the kind fallback into FIX.
        assert_eq!(
            canonical_tool_phase("mystery", ModuleKind::Config, "mystery:report"),
            ToolPhase::Fix
        );
    }
}
