use super::*;
use crate::fleet::{
    default_fleet_dir, diff_findings_bounded, fleet_status, load_fleet_targets, query_corpus_rows,
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
            operational_tool(fleet_register_tool(), global_write_policy()),
            operational_tool(fleet_ingest_tool(), global_write_policy()),
            operational_tool(fleet_status_tool(), global_read_policy()),
            operational_tool(fleet_findings_tool(), global_read_policy()),
            operational_tool(fleet_diff_findings_tool(), global_read_policy()),
        ],
        vec![],
    )
}

fn operational_tool(mut tool: ToolDescriptor, policy: ToolPolicy) -> ToolDescriptor {
    tool.options.push(opt("allowanceRef", OptionType::Json,
        "Retained reference input checked during preparation. This operational action starts no model requests or investigation work.").advanced());
    tool.with_policy(policy).without_phase_result()
}

const fn global_write_policy() -> ToolPolicy {
    tool_policy(
        ToolPhase::Operate,
        RuntimeRequirement::Never,
        ToolEffect::WorkspaceWrite,
        WorkspaceRequirement::Optional,
        FindingStoreRequirement::Optional,
    )
}

const fn global_read_policy() -> ToolPolicy {
    tool_policy(
        ToolPhase::Operate,
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
            opt(
                "remote",
                OptionType::String,
                "Upstream remote, e.g. github.com/org/repo.",
            ),
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
        "One-screen fleet scorecard: per target, baselines, last-scanned revision, \
         critical/high record counts, and corpus quality flags. Counts are projections, not actionability verdicts.",
    )
}

fn fleet_findings_tool() -> ToolDescriptor {
    tool_with_options(
        "fleet:findings",
        "Query the derived fleet corpus across targets.",
        vec![
            opt(
                "class",
                OptionType::String,
                "Closed-enum class filter, e.g. mem-oob-write.",
            ),
            opt(
                "severity",
                OptionType::String,
                "Severity filter: critical|high|medium|low|info.",
            ),
            opt("limit", OptionType::Int, "Maximum current finding rows.")
                .integer_range(1, 10_000)
                .default(json!(100)),
        ],
    )
}

fn fleet_diff_findings_tool() -> ToolDescriptor {
    tool_with_options(
        "fleet:diff-findings",
        "Compare recorded observation presence across two revisions. Source-proximity groups are uncertain matches; fix status requires a separate human decision. Legacy lead names remain for compatibility.",
        vec![
            opt("target", OptionType::String, "Fleet target id.").required(),
            opt("base", OptionType::String, "Base revision SHA.").required(),
            opt("head", OptionType::String, "Head revision SHA.").required(),
            opt("maxRows", OptionType::Int, "Maximum recorded observations across both revisions. Refuses larger comparisons without truncation.")
                .integer_range(1, 10_000).default(json!(10_000)),
        ],
    )
}

pub(in crate::modules) fn run_fleet_diff_findings(input: &Value) -> Result<Value> {
    let target = required_string(input, "target")?;
    let base = required_string(input, "base")?;
    let head = required_string(input, "head")?;
    let limit = input["maxRows"]
        .as_u64()
        .context("maxRows is required after preparation")?;
    let report = diff_findings_bounded(
        &default_fleet_dir()?,
        &target,
        &base,
        &head,
        usize::try_from(limit)?,
    )?;
    let output = fleet_comparison_text(&report);
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({ "report": report }),
    ))
}

fn fleet_comparison_text(report: &crate::fleet::DiffFindingsReport) -> String {
    let mut lines = vec![format!("Recorded observation comparison · {} · {} group(s)", report.target_id, report.entries.len()),
        format!("Base: {}\nHead: {}", report.base_sha, report.head_sha),
        "Groups use nearby source locations; matches remain uncertain. Scan conditions and coverage may differ.".into(),
        "Fix status requires a separate human decision. Same SHA can include dirty content and different runs.".into()];
    lines.extend(report.entries.iter().map(|entry| {
        format!(
            "{} · {} · {}\n  {} · {}",
            entry.lead.presence(),
            entry.severity,
            entry.title,
            entry.file,
            entry.cluster_id
        )
    }));
    lines.join("\n")
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
        "Fleet registry is empty. Run fleet:register first."
    );
    let report = rebuild_corpus(&fleet_dir, &targets)?;
    let mut output = format!(
        "fleet:ingest · {} row(s) from {} target(s) · {} quality flag(s) · {} skipped",
        report.rows,
        report.targets_ingested,
        report.quality_flag_count,
        report.targets_skipped.len(),
    );
    for skipped in &report.targets_skipped {
        output.push_str(&format!("\nSkipped target: {skipped}"));
    }
    let data = json!({"report":report});
    if report.targets_skipped.is_empty() {
        return Ok(crate::module_result::completed_output_result(
            output.clone(),
            output,
            data,
        ));
    }
    Ok(crate::module_result::partial_output_result(
        output.clone(),
        output,
        report
            .targets_skipped
            .iter()
            .map(|text| json!(text))
            .collect(),
        data,
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
        "  {:<16} rev {} · {} baseline(s) · {}C {}H records · {} flag(s)",
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
    let output = fleet_findings_text(&rows, limit);
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({ "findings": rows }),
    ))
}

fn fleet_findings_text(rows: &[crate::fleet::CorpusFindingRow], limit: usize) -> String {
    let mut lines = vec![
        format!(
            "fleet:findings · {} current row(s) · requested limit {limit}",
            rows.len()
        ),
        "Bounded query of current records; totals, coverage and actionability are not established."
            .into(),
    ];
    lines.extend(rows.iter().map(|row| {
        format!(
            "{} · {} · {}\n  {}:{} · {}",
            row.target_id, row.severity, row.title, row.file, row.line, row.fingerprint
        )
    }));
    lines.join("\n")
}

#[cfg(test)]
mod scorecard_tests {
    use super::*;

    fn status(reachable: bool, sha: Option<&str>) -> FleetTargetStatus {
        FleetTargetStatus {
            target_id: "target-a".to_string(),
            path: "/data/target-a".to_string(),
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
            targets: vec![status(true, Some("a1b2c3d4e5f6")), status(false, None)],
            corpus_rows: 41,
            corpus_quality_flags: 3,
        };

        let card = fleet_scorecard(&report);

        assert!(card.contains("2 target(s) · 41 corpus row(s) · 3 quality flag(s)"));
        assert!(card.contains("rev a1b2c3d4 (main) · 3 baseline(s) · 2C 5H records · 1 flag(s)"));
        assert!(card.contains("UNREACHABLE · /data/target-a"));
    }

    #[test]
    fn a_target_without_scan_baselines_reads_never_scanned() {
        assert!(scorecard_line(&status(true, None)).contains("rev never-scanned"));
    }

    #[test]
    fn operational_fleet_tools_preserve_preparation_without_completing_map() {
        let registry = ModuleRegistry::with_v2_builtins();
        let config = crate::V2Config::default();
        let context = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        for name in [
            "fleet:register",
            "fleet:ingest",
            "fleet:status",
            "fleet:findings",
            "fleet:diff-findings",
        ] {
            let tool = registry.resolve_tool(name).unwrap();
            assert_eq!(tool.phase, ToolPhase::Operate, "{name}");
            assert_eq!(tool.runtime_requirement, RuntimeRequirement::Never);
            assert!(!tool.phase_result, "{name}");
            assert!(tool
                .options
                .iter()
                .any(|option| option.name == "allowanceRef"));
        }
        for value in [
            json!({"limit":0}),
            json!({"limit":10001}),
            json!({"unknown":true}),
        ] {
            assert!(registry
                .prepare_dispatch_input("fleet:findings", value, &context, None)
                .is_err());
        }
        let comparison = json!({"target":"owned","base":"a","head":"b"});
        assert!(registry
            .prepare_dispatch_input("fleet:diff-findings", comparison.clone(), &context, None)
            .is_ok());
        for limit in [0, 10001] {
            let mut invalid = comparison.clone();
            invalid["maxRows"] = json!(limit);
            assert!(registry
                .prepare_dispatch_input("fleet:diff-findings", invalid, &context, None)
                .is_err());
        }
    }

    #[test]
    fn comparison_text_exposes_presence_and_uncertainty() {
        let report = crate::fleet::DiffFindingsReport {
            target_id: "owned".into(),
            base_sha: "a".repeat(40),
            head_sha: "b".repeat(40),
            entries: vec![crate::fleet::DiffFindingEntry {
                cluster_id: "package.json:1".into(),
                lead: crate::fleet::FindingLead::BackportGap,
                file: "package.json".into(),
                class: "other".into(),
                severity: "low".into(),
                title: "Owned policy observation".into(),
            }],
        };
        let text = fleet_comparison_text(&report);
        assert!(text.contains("base-only · low · Owned policy observation"));
        assert!(text.contains("matches remain uncertain"));
        assert!(text.contains("Fix status requires a separate human decision"));
        assert!(text.contains(&report.base_sha) && text.contains(&report.head_sha));
        assert!(!text.contains("fixed") && !text.contains("backport-gap"));
    }

    #[test]
    fn findings_text_shows_bounded_records_without_actionability_claims() {
        let row = crate::fleet::CorpusFindingRow {
            target_id: "owned".into(),
            fingerprint: "owned-policy".into(),
            file: "package.json".into(),
            line: 1,
            class: "other".into(),
            severity: "low".into(),
            cluster_id: "package.json:1".into(),
            revision_sha: None,
            branch: None,
            tool: "owned-policy".into(),
            title: "Owned package policy".into(),
            quality_flags: "no-revision".into(),
        };
        let output = fleet_findings_text(&[row], 2);
        assert!(output.contains("1 current row(s) · requested limit 2"));
        assert!(output.contains("owned · low · Owned package policy"));
        assert!(output.contains("package.json:1 · owned-policy"));
        assert!(output.contains("totals, coverage and actionability are not established"));
    }
}
