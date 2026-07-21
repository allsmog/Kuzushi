use super::*;
use crate::fleet::{
    default_fleet_dir, diff_findings, fleet_status, load_fleet_targets, query_corpus_rows,
    rebuild_corpus, register_fleet_target, FleetStatusReport, FleetTarget, FleetTargetStatus,
};
use std::path::PathBuf;

/// Fleet tools operate on the operator-global `~/.kuzushi/v3/fleet/` store,
/// so they need no active workspace: targets come from the registry.
pub(crate) fn fleet_module() -> BuiltinModule {
    builtin_module(
        "fleet",
        "Fleet",
        ModuleKind::Intel,
        "Multi-target registry, derived findings corpus, and one-screen fleet status.",
        vec![
            fleet_register_tool().with_policy(global_write_policy()),
            fleet_ingest_tool().with_policy(global_write_policy()),
            fleet_status_tool().with_policy(global_read_policy()),
            fleet_findings_tool().with_policy(global_read_policy()),
            fleet_diff_findings_tool().with_policy(global_read_policy()),
        ],
        vec![],
    )
}

const fn global_write_policy() -> ToolPolicy {
    tool_policy(
        ToolPhase::Map,
        RuntimeRequirement::Never,
        ToolEffect::WorkspaceWrite,
        WorkspaceRequirement::Optional,
        FindingStoreRequirement::Optional,
    )
}

const fn global_read_policy() -> ToolPolicy {
    tool_policy(
        ToolPhase::Map,
        RuntimeRequirement::Never,
        ToolEffect::Read,
        WorkspaceRequirement::Optional,
        FindingStoreRequirement::Optional,
    )
}

fn fleet_register_tool() -> ToolDescriptor {
    tool_with_options(
        "fleet:register",
        "Register or update a scan target in the fleet registry (targets.toml). \
         Idempotent by id.",
        vec![
            opt("id", OptionType::String, "Stable fleet-wide target id.").required(),
            opt("path", OptionType::Path, "Absolute target root path.")
                .external_read()
                .required(),
            opt("remote", OptionType::String, "Upstream remote, e.g. github.com/org/repo."),
            opt("defaultBranch", OptionType::String, "Default branch name.")
                .aliases(&["default_branch"]),
            opt("label", OptionType::String, "Human-facing label."),
        ],
    )
}

fn fleet_ingest_tool() -> ToolDescriptor {
    tool(
        "fleet:ingest",
        "Rebuild the derived fleet corpus from every registered target's findings store. \
         Per-target stores stay the truth; contract violations become counted quality flags.",
    )
}

fn fleet_status_tool() -> ToolDescriptor {
    tool(
        "fleet:status",
        "One-screen fleet scorecard: per target, baselines, last-scanned revision, open \
         critical/high counts, and corpus quality-flag drift.",
    )
}

fn fleet_findings_tool() -> ToolDescriptor {
    tool_with_options(
        "fleet:findings",
        "Query the derived fleet corpus across targets.",
        vec![
            opt("class", OptionType::String, "Closed-enum class filter, e.g. mem-oob-write."),
            opt("severity", OptionType::String, "Severity filter: critical|high|medium|low|info."),
            opt("limit", OptionType::Int, "Maximum rows.").default(json!(100)),
        ],
    )
}

fn fleet_diff_findings_tool() -> ToolDescriptor {
    tool_with_options(
        "fleet:diff-findings",
        "Join one target's corpus rows across two revisions by dedup cluster and label \
         each cluster branch-delta (head only), backport-gap (base only), or both.",
        vec![
            opt("target", OptionType::String, "Fleet target id.").required(),
            opt("base", OptionType::String, "Base revision SHA.").required(),
            opt("head", OptionType::String, "Head revision SHA.").required(),
        ],
    )
}

pub(in crate::modules) fn run_fleet_diff_findings(input: &Value) -> Result<Value> {
    let target = required_string(input, "target")?;
    let base = required_string(input, "base")?;
    let head = required_string(input, "head")?;
    let report = diff_findings(&default_fleet_dir()?, &target, &base, &head)?;
    let output = format!(
        "fleet:diff-findings · {} · {} cluster(s) labeled",
        target,
        report.entries.len()
    );
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({ "report": report }),
    ))
}

pub(in crate::modules) fn run_fleet_register(input: &Value) -> Result<Value> {
    let target = fleet_target_from_input(input)?;
    let targets = register_fleet_target(&default_fleet_dir()?, target.clone())?;
    let output = format!(
        "fleet:register · {} registered · {} target(s) in fleet",
        target.id,
        targets.len()
    );
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({ "registered": target, "targets": targets }),
    ))
}

fn fleet_target_from_input(input: &Value) -> Result<FleetTarget> {
    let id = required_string(input, "id")?;
    let path = PathBuf::from(required_string(input, "path")?);
    Ok(FleetTarget {
        id,
        path,
        remote: optional_string(input, "remote"),
        default_branch: optional_string(input, "defaultBranch"),
        label: optional_string(input, "label"),
    })
}

fn required_string(input: &Value, key: &str) -> Result<String> {
    optional_string(input, key).with_context(|| format!("fleet tool requires {key}=<value>"))
}

fn optional_string(input: &Value, key: &str) -> Option<String> {
    input
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(in crate::modules) fn run_fleet_ingest() -> Result<Value> {
    let fleet_dir = default_fleet_dir()?;
    let targets = load_fleet_targets(&fleet_dir)?;
    anyhow::ensure!(
        !targets.is_empty(),
        "fleet registry is empty — run fleet:register first"
    );
    let report = rebuild_corpus(&fleet_dir, &targets)?;
    let output = format!(
        "fleet:ingest · {} row(s) from {} target(s) · {} quality flag(s) · {} skipped",
        report.rows,
        report.targets_ingested,
        report.quality_flag_count,
        report.targets_skipped.len(),
    );
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({ "report": report }),
    ))
}

pub(in crate::modules) fn run_fleet_status() -> Result<Value> {
    let fleet_dir = default_fleet_dir()?;
    let targets = load_fleet_targets(&fleet_dir)?;
    let report = fleet_status(&fleet_dir, &targets)?;
    let output = fleet_scorecard(&report);
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({ "report": report }),
    ))
}

/// The one-screen dashboard: identical text in shell receipts, `kuzushi run`
/// stdout, and plain output, because it is the tool's own output.
fn fleet_scorecard(report: &FleetStatusReport) -> String {
    let mut lines = vec![format!(
        "fleet:status · {} target(s) · {} corpus row(s) · {} quality flag(s)",
        report.targets.len(),
        report.corpus_rows,
        report.corpus_quality_flags,
    )];
    lines.extend(report.targets.iter().map(scorecard_line));
    lines.join("\n")
}

fn scorecard_line(status: &FleetTargetStatus) -> String {
    if !status.reachable {
        return format!("  {:<16} UNREACHABLE · {}", status.target_id, status.path);
    }
    format!(
        "  {:<16} rev {} · {} baseline(s) · {}C {}H open · {} flag(s)",
        status.target_id,
        revision_label(status),
        status.baseline_count,
        status.critical_open,
        status.high_open,
        status.quality_flags,
    )
}

fn revision_label(status: &FleetTargetStatus) -> String {
    let Some(sha) = status.last_scan_sha.as_deref() else {
        return "never-scanned".to_string();
    };
    let short: String = sha.chars().take(8).collect();
    let branch = status.last_scan_branch.as_deref().unwrap_or("?");
    let dirty = if status.last_scan_dirty == Some(true) {
        " dirty"
    } else {
        ""
    };
    format!("{short} ({branch}{dirty})")
}

pub(in crate::modules) fn run_fleet_findings(input: &Value) -> Result<Value> {
    let fleet_dir = default_fleet_dir()?;
    let class = optional_string(input, "class");
    let severity = optional_string(input, "severity");
    let limit = input
        .get("limit")
        .and_then(Value::as_u64)
        .map(|limit| limit as usize)
        .filter(|limit| *limit > 0)
        .unwrap_or(100);
    let rows = query_corpus_rows(&fleet_dir, class.as_deref(), severity.as_deref(), limit)?;
    let output = format!("fleet:findings · {} row(s)", rows.len());
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({ "findings": rows }),
    ))
}

#[cfg(test)]
mod scorecard_tests {
    use super::*;

    fn status(reachable: bool, sha: Option<&str>) -> FleetTargetStatus {
        FleetTargetStatus {
            target_id: "monorepo".to_string(),
            path: "/data/monorepo".to_string(),
            reachable,
            baseline_count: 3,
            last_scan_sha: sha.map(str::to_string),
            last_scan_branch: sha.map(|_| "main".to_string()),
            last_scan_dirty: sha.map(|_| false),
            critical_open: 2,
            high_open: 5,
            quality_flags: 1,
        }
    }

    #[test]
    fn scorecard_shows_revision_counts_and_reachability() {
        let report = FleetStatusReport {
            targets: vec![
                status(true, Some("a1b2c3d4e5f6")),
                status(false, None),
            ],
            corpus_rows: 41,
            corpus_quality_flags: 3,
        };

        let card = fleet_scorecard(&report);

        assert!(card.contains("2 target(s) · 41 corpus row(s) · 3 quality flag(s)"));
        assert!(card.contains("rev a1b2c3d4 (main) · 3 baseline(s) · 2C 5H open · 1 flag(s)"));
        assert!(card.contains("UNREACHABLE · /data/monorepo"));
    }

    #[test]
    fn a_target_without_scan_baselines_reads_never_scanned() {
        assert!(scorecard_line(&status(true, None)).contains("rev never-scanned"));
    }
}
