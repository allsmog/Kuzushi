use super::*;
use crate::ui_view_models::{
    context_snapshot_relative_path, findings_db_relative_path, threat_model_relative_path,
};

const MODULE_PLAYBOOKS: &[(&str, ModulePlaybook)] = &[
    (
        "context",
        ModulePlaybook {
            run: PlaybookText::ContextSnapshotRun,
            needs: "target workspace",
            output: PlaybookText::ContextSnapshotPath,
            inspect: "context status · context regen repo",
        },
    ),
    (
        "recon",
        ModulePlaybook {
            run: PlaybookText::Static("run nmap, subdomain, or http-fingerprint with a target"),
            needs: "target host or active workspace",
            output: PlaybookText::Static("recon notes and optional findings"),
            inspect: "workspace · findings · use threat-model",
        },
    ),
    (
        "threat-model",
        ModulePlaybook {
            run: PlaybookText::Static(
                "threats regen proposes a STRIDE / DFD patch; run . dispatches threat-model:build",
            ),
            needs: "target, context, explicit model",
            output: PlaybookText::ThreatModelPath,
            inspect: "threats summary · threats edit · threats regen",
        },
    ),
    (
        "sast",
        ModulePlaybook {
            run: PlaybookText::Static("next opens guided Scan; run . dispatches sast:scan"),
            needs: "target, scanner/task config",
            output: PlaybookText::FindingsDbPath,
            inspect: "tasks · findings · use triage",
        },
    ),
    (
        "semgrep",
        ModulePlaybook {
            run: PlaybookText::Static("run . dispatches semgrep:scan for fast pattern findings"),
            needs: "target and optional scanner config",
            output: PlaybookText::FindingsDbPath,
            inspect: "findings · use triage · use verify",
        },
    ),
    (
        "codeql",
        ModulePlaybook {
            run: PlaybookText::Static("run . dispatches codeql:scan for semantic findings"),
            needs: "target and CodeQL language/database options",
            output: PlaybookText::FindingsDbPathWithSarif,
            inspect: "findings · use triage · use verify",
        },
    ),
    (
        "dep-hygiene",
        ModulePlaybook {
            run: PlaybookText::Static("run . dispatches dep-hygiene:check for manifest risk"),
            needs: "target with dependency manifests",
            output: PlaybookText::FindingsDbPath,
            inspect: "findings · use triage · use report",
        },
    ),
    (
        "cargo-audit",
        ModulePlaybook {
            run: PlaybookText::Static("run . dispatches cargo-audit:scan for RustSec advisories"),
            needs: "target with Cargo.lock and cargo-audit installed",
            output: PlaybookText::FindingsDbPath,
            inspect: "findings · use triage · use report",
        },
    ),
    (
        "govulncheck",
        ModulePlaybook {
            run: PlaybookText::Static(
                "run . dispatches govulncheck:scan for Go reachable vulnerabilities",
            ),
            needs: "target with Go packages and govulncheck installed",
            output: PlaybookText::FindingsDbPath,
            inspect: "findings · use triage · use report",
        },
    ),
    (
        "secret-scan",
        ModulePlaybook {
            run: PlaybookText::Static("run . dispatches secret-scan:scan for credential findings"),
            needs: "target source or config files",
            output: PlaybookText::FindingsDbPath,
            inspect: "findings · use triage · use report",
        },
    ),
    (
        "iac-scan",
        ModulePlaybook {
            run: PlaybookText::Static(
                "run . dispatches iac-scan:scan for IaC misconfiguration findings",
            ),
            needs: "target with Dockerfile, Actions, or Terraform files",
            output: PlaybookText::FindingsDbPath,
            inspect: "findings · use triage · use report",
        },
    ),
    (
        "license-scan",
        ModulePlaybook {
            run: PlaybookText::Static(
                "run . dispatches license-scan:scan for package license risk",
            ),
            needs: "target with package manifests",
            output: PlaybookText::FindingsDbPath,
            inspect: "findings · use triage · use report",
        },
    ),
    (
        "sbom-scan",
        ModulePlaybook {
            run: PlaybookText::Static("run . dispatches sbom-scan:scan for dependency inventory"),
            needs: "target with package manifests",
            output: PlaybookText::Static("SBOM-style component inventory"),
            inspect: "run sbom-scan:scan · use module-recommender",
        },
    ),
    (
        "carlini-threat-hunt",
        ModulePlaybook {
            run: PlaybookText::Static(
                "run . after threat-model:build to start adversarial actor hunts",
            ),
            needs: "target, threat model, explicit model",
            output: PlaybookText::Static("threat-hunt runs and promoted findings"),
            inspect: "show trace · findings · use verify",
        },
    ),
    (
        "agentic-sast",
        ModulePlaybook {
            run: PlaybookText::Static(
                "run . or run agentic-sast:scan starts dataflow and variant hunting agents",
            ),
            needs: "target, context, explicit model",
            output: PlaybookText::Static("agentic traces and promoted findings"),
            inspect: "findings · show trace · use verify",
        },
    ),
];

const DEFAULT_PLAYBOOK: ModulePlaybook = ModulePlaybook {
    run: PlaybookText::Static("run . to dispatch the primary tool for this module"),
    needs: "tool-specific options; inspect options .",
    output: PlaybookText::Static("structured result or artifact when emitted"),
    inspect: "options . · prompts · tune · back",
};

#[derive(Clone, Copy)]
struct ModulePlaybook {
    run: PlaybookText,
    needs: &'static str,
    output: PlaybookText,
    inspect: &'static str,
}

#[derive(Clone, Copy)]
enum PlaybookText {
    Static(&'static str),
    ContextSnapshotRun,
    ContextSnapshotPath,
    FindingsDbPath,
    FindingsDbPathWithSarif,
    ThreatModelPath,
}

impl PlaybookText {
    fn render(self) -> String {
        match self {
            Self::Static(value) => value.to_string(),
            Self::ContextSnapshotRun => format!(
                "context build or run . writes {}",
                context_snapshot_relative_path()
            ),
            Self::ContextSnapshotPath => context_snapshot_relative_path().to_string(),
            Self::FindingsDbPath => findings_db_relative_path().to_string(),
            Self::FindingsDbPathWithSarif => {
                format!("{} and optional SARIF", findings_db_relative_path())
            }
            Self::ThreatModelPath => threat_model_relative_path().to_string(),
        }
    }
}

pub(crate) fn module_playbook_lines(
    module_id: &str,
    primary_tool: &str,
    width: u16,
) -> Vec<Line<'static>> {
    let mut lines = vec![divider("NEXT", width)];
    let playbook = module_playbook(module_id);
    append_run_rows(&mut lines, primary_tool, playbook, width);
    append_help_row(&mut lines, playbook.inspect);
    lines
}

fn module_playbook(module_id: &str) -> ModulePlaybook {
    MODULE_PLAYBOOKS
        .iter()
        .find_map(|(id, playbook)| (*id == module_id).then_some(*playbook))
        .unwrap_or(DEFAULT_PLAYBOOK)
}

fn append_run_rows(
    lines: &mut Vec<Line<'static>>,
    primary_tool: &str,
    playbook: ModulePlaybook,
    width: u16,
) {
    let resolution = run_resolution(primary_tool);
    let run = playbook.run.render();
    let output = playbook.output.render();
    lines.push(playbook_row("run .", &fit(&resolution, width as usize)));
    lines.push(playbook_row("tool", &fit(&run, width as usize)));
    lines.push(playbook_row("needs", &fit(playbook.needs, width as usize)));
    lines.push(playbook_row(
        "options",
        &fit(&options_row_text(primary_tool), width as usize),
    ));
    lines.push(playbook_row("output", &fit(&output, width as usize)));
}

fn playbook_row(label: &str, body: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(" · ", theme::muted()),
        Span::styled(format!("{label:<8}"), theme::subtle()),
        Span::styled(body.to_string(), theme::primary()),
    ])
}

fn run_resolution(primary_tool: &str) -> String {
    if primary_tool == "no-tool" {
        return "no target — this module exposes no shell tool".to_string();
    }
    format!(
        "dispatches {primary_tool} (shell); terminal: kuzushi --target . run {primary_tool} --input '{{}}'"
    )
}

fn options_row_text(primary_tool: &str) -> String {
    if primary_tool == "sast:scan" {
        return "options sast:scan before scan; show advanced sast:scan for budgets/model"
            .to_string();
    }
    if primary_tool == "no-tool" {
        return "options . when this module exposes tunable tool knobs".to_string();
    }
    "options . before run; show advanced . for hidden knobs".to_string()
}

fn append_help_row(lines: &mut Vec<Line<'static>>, inspect: &str) {
    // The `help` line is a `cmd · cmd · cmd` list — accent each command
    // and tint separators subtle, matching `command_list_line`.  Keep
    // the leading ` · ` glyph + `help ` label so the prefix still scans
    // as transcript context (the divider above is `── NEXT ──`, the row
    // is "help  <commands>").
    let commands: Vec<&str> = inspect.split(" · ").collect();
    let mut spans: Vec<Span<'static>> = vec![
        Span::styled(" · ", theme::muted()),
        Span::styled("help ", theme::subtle()),
    ];
    for (i, cmd) in commands.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" · ", theme::subtle()));
        }
        spans.push(Span::styled((*cmd).to_string(), theme::accent()));
    }
    lines.push(Line::from(spans));
}
