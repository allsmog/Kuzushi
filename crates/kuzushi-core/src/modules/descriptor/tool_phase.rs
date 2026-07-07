use super::ModuleKind;
use serde::{Deserialize, Serialize};

/// Canonical journey phase a tool belongs to. This is the single source of
/// truth that the CLI (`tools --json`), the shell Tools/Catalog views, and the
/// `ToolQuery` grammar all read — replacing the previously triplicated
/// phase/category tables that lived only in the TUI.
///
/// This is *display grouping* metadata, not execution-ordering input: it never
/// participates in dispatch, runtime-requirement resolution, or DAG ordering.
/// The drift-guard tests assert exactly that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ToolPhase {
    /// 組 build context, scope, inventory, and threat model.
    Map,
    /// 崩 find candidate vulnerabilities and security signals.
    Hunt,
    /// 作 rank, triage, verify, and inspect findings.
    Confirm,
    /// 掛 patch findings and produce reports.
    Fix,
    /// Configure providers, models, catalogs, and policy — also the honest
    /// "expert/other" bucket for tools (including dynamic/SDK modules) that
    /// declare no phase.
    #[default]
    Operate,
}

impl ToolPhase {
    /// Canonical group order shared by every phase-grouped surface.
    pub const ORDER: [ToolPhase; 5] = [
        ToolPhase::Map,
        ToolPhase::Hunt,
        ToolPhase::Confirm,
        ToolPhase::Fix,
        ToolPhase::Operate,
    ];

    /// Uppercase group label (`MAP` … `OPERATE`).
    pub fn label(self) -> &'static str {
        match self {
            ToolPhase::Map => "MAP",
            ToolPhase::Hunt => "HUNT",
            ToolPhase::Confirm => "CONFIRM",
            ToolPhase::Fix => "FIX",
            ToolPhase::Operate => "OPERATE",
        }
    }

    /// Judo glyph for the phase, `None` for the OPERATE/expert bucket.
    pub fn kanji(self) -> Option<&'static str> {
        match self {
            ToolPhase::Map => Some("組"),
            ToolPhase::Hunt => Some("崩"),
            ToolPhase::Confirm => Some("作"),
            ToolPhase::Fix => Some("掛"),
            ToolPhase::Operate => None,
        }
    }

    /// One-line statement of what the phase is for.
    pub fn hint(self) -> &'static str {
        match self {
            ToolPhase::Map => "build context, scope, inventory, and threat model",
            ToolPhase::Hunt => "find candidate vulnerabilities and security signals",
            ToolPhase::Confirm => "rank, triage, verify, and inspect findings",
            ToolPhase::Fix => "patch findings and produce reports",
            ToolPhase::Operate => "configure providers, models, catalogs, and policy",
        }
    }

    /// Lowercase machine token (`map` … `operate`) for query grammar output.
    pub fn as_str(self) -> &'static str {
        match self {
            ToolPhase::Map => "map",
            ToolPhase::Hunt => "hunt",
            ToolPhase::Confirm => "confirm",
            ToolPhase::Fix => "fix",
            ToolPhase::Operate => "operate",
        }
    }

    /// Parse a phase from an operator token — plain word, romaji, or kanji.
    pub fn parse(input: &str) -> Option<ToolPhase> {
        match input.trim().to_ascii_lowercase().as_str() {
            "map" | "1" | "kumi" | "kumi-kata" | "組" => Some(ToolPhase::Map),
            "hunt" | "2" | "kuzushi" | "崩" => Some(ToolPhase::Hunt),
            "confirm" | "3" | "tsukuri" | "作" => Some(ToolPhase::Confirm),
            "fix" | "4" | "kake" | "掛" => Some(ToolPhase::Fix),
            "operate" | "5" | "expert" | "other" => Some(ToolPhase::Operate),
            _ => None,
        }
    }
}

/// The single canonical mapping from a tool to its journey phase, transcribed
/// from the TUI's former `tool_group_key`/`fallback_tool_group` tables. Every
/// built-in tool is stamped with this at registration time so the descriptor
/// itself carries the truth.
pub fn canonical_tool_phase(module_id: &str, kind: ModuleKind, tool_name: &str) -> ToolPhase {
    match module_id {
        "context" | "context-lite" | "recon" | "threat-model" | "workspace" | "x-ray"
        | "entry-points" | "cpg" | "codeql-db" | "threat-intel" | "randori" | "ndiff" => {
            ToolPhase::Map
        }
        "sast" | "semgrep" | "codeql" | "agentic-sast" | "taint-iris" | "taint-iris-next"
        | "secret-scan" | "iac-scan" | "cargo-audit" | "govulncheck" | "dep-hygiene"
        | "android-apk" | "chrome-rce" | "carlini-threat-hunt" | "uaf-hunt" | "exploit-chain"
        | "systems-hunt" => ToolPhase::Hunt,
        "findings" | "triage" | "verify" | "classifier-gate" | "deep-audit" | "threat-leads" => {
            ToolPhase::Confirm
        }
        "patch" | "report" => ToolPhase::Fix,
        _ => fallback_tool_phase(kind, tool_name),
    }
}

fn fallback_tool_phase(kind: ModuleKind, tool_name: &str) -> ToolPhase {
    if tool_name.contains("patch") || tool_name.contains("report") {
        return ToolPhase::Fix;
    }
    match kind {
        ModuleKind::Offense | ModuleKind::Scan | ModuleKind::Defense => ToolPhase::Hunt,
        ModuleKind::Intel | ModuleKind::Context | ModuleKind::Workspace => ToolPhase::Map,
        ModuleKind::Findings | ModuleKind::Triage => ToolPhase::Confirm,
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
        assert_eq!(ToolPhase::ORDER.len(), 5);
        assert_eq!(ToolPhase::Map.label(), "MAP");
        assert_eq!(ToolPhase::Operate.label(), "OPERATE");
        assert_eq!(ToolPhase::Hunt.kanji(), Some("崩"));
        assert_eq!(ToolPhase::Operate.kanji(), None);
    }

    #[test]
    fn default_is_operate() {
        assert_eq!(ToolPhase::default(), ToolPhase::Operate);
    }

    #[test]
    fn parse_accepts_word_romaji_and_kanji() {
        assert_eq!(ToolPhase::parse("hunt"), Some(ToolPhase::Hunt));
        assert_eq!(ToolPhase::parse("KUZUSHI"), Some(ToolPhase::Hunt));
        assert_eq!(ToolPhase::parse("崩"), Some(ToolPhase::Hunt));
        assert_eq!(ToolPhase::parse("operate"), Some(ToolPhase::Operate));
        assert_eq!(ToolPhase::parse("nope"), None);
    }

    #[test]
    fn canonical_phase_matches_curated_modules() {
        assert_eq!(
            canonical_tool_phase("semgrep", ModuleKind::Scan, "semgrep:scan"),
            ToolPhase::Hunt
        );
        assert_eq!(
            canonical_tool_phase("threat-model", ModuleKind::Intel, "threat-model:build"),
            ToolPhase::Map
        );
        assert_eq!(
            canonical_tool_phase("triage", ModuleKind::Triage, "triage:run"),
            ToolPhase::Confirm
        );
        assert_eq!(
            canonical_tool_phase("patch", ModuleKind::Offense, "patch:finding"),
            ToolPhase::Fix
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
