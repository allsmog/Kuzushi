use super::*;

const MODULE_PLAYBOOKS: &[(&str, ModulePlaybook)] = &[
    (
        "context",
        ModulePlaybook {
            run: "context build or run . writes .kuzushi/context-snapshot.json",
            needs: "target workspace",
            output: ".kuzushi/context-snapshot.json",
            inspect: "context status · context regen repo",
        },
    ),
    (
        "recon",
        ModulePlaybook {
            run: "run nmap, subdomain, or http-fingerprint with a target",
            needs: "target host or active workspace",
            output: "recon notes and optional findings",
            inspect: "workspace · findings · use threat-model",
        },
    ),
    (
        "threat-model",
        ModulePlaybook {
            run: "threats regen proposes a STRIDE / DFD patch; run . dispatches threat-model:build",
            needs: "target, context, explicit model",
            output: ".kuzushi/threat-model.json",
            inspect: "threats summary · threats edit · threats regen",
        },
    ),
    (
        "sast",
        ModulePlaybook {
            run: "scan runs configured scanners; run . dispatches sast:scan",
            needs: "target, scanner/task config",
            output: ".kuzushi/v2/findings.sqlite3",
            inspect: "tasks · findings · use triage",
        },
    ),
    (
        "semgrep",
        ModulePlaybook {
            run: "run . dispatches semgrep:scan for fast pattern findings",
            needs: "target and optional scanner config",
            output: ".kuzushi/v2/findings.sqlite3",
            inspect: "findings · use triage · use verify",
        },
    ),
    (
        "codeql",
        ModulePlaybook {
            run: "run . dispatches codeql:scan for semantic findings",
            needs: "target and CodeQL language/database options",
            output: ".kuzushi/v2/findings.sqlite3 and optional SARIF",
            inspect: "findings · use triage · use verify",
        },
    ),
    (
        "dep-hygiene",
        ModulePlaybook {
            run: "run . dispatches dep-hygiene:check for manifest risk",
            needs: "target with dependency manifests",
            output: ".kuzushi/v2/findings.sqlite3",
            inspect: "findings · use triage · use report",
        },
    ),
    (
        "cargo-audit",
        ModulePlaybook {
            run: "run . dispatches cargo-audit:scan for RustSec advisories",
            needs: "target with Cargo.lock and cargo-audit installed",
            output: ".kuzushi/v2/findings.sqlite3",
            inspect: "findings · use triage · use report",
        },
    ),
    (
        "secret-scan",
        ModulePlaybook {
            run: "run . dispatches secret-scan:scan for credential findings",
            needs: "target source or config files",
            output: ".kuzushi/v2/findings.sqlite3",
            inspect: "findings · use triage · use report",
        },
    ),
    (
        "iac-scan",
        ModulePlaybook {
            run: "run . dispatches iac-scan:scan for IaC misconfiguration findings",
            needs: "target with Dockerfile, Actions, or Terraform files",
            output: ".kuzushi/v2/findings.sqlite3",
            inspect: "findings · use triage · use report",
        },
    ),
    (
        "license-scan",
        ModulePlaybook {
            run: "run . dispatches license-scan:scan for package license risk",
            needs: "target with package manifests",
            output: ".kuzushi/v2/findings.sqlite3",
            inspect: "findings · use triage · use report",
        },
    ),
    (
        "sbom-scan",
        ModulePlaybook {
            run: "run . dispatches sbom-scan:scan for dependency inventory",
            needs: "target with package manifests",
            output: "SBOM-style component inventory",
            inspect: "run sbom-scan:scan · use module-recommender",
        },
    ),
    (
        "carlini-threat-hunt",
        ModulePlaybook {
            run: "run . after threat-model:build to start adversarial actor hunts",
            needs: "target, threat model, explicit model",
            output: "threat-hunt runs and promoted findings",
            inspect: "show trace · findings · use verify",
        },
    ),
    (
        "agentic-sast",
        ModulePlaybook {
            run: "run . or run agentic-sast:scan starts dataflow and variant hunting agents",
            needs: "target, context, explicit model",
            output: "agentic traces and promoted findings",
            inspect: "findings · show trace · use verify",
        },
    ),
];

const DEFAULT_PLAYBOOK: ModulePlaybook = ModulePlaybook {
    run: "run . to dispatch the primary tool for this module",
    needs: "tool-specific options; inspect options .",
    output: "structured result or artifact when emitted",
    inspect: "options . · prompts · tune · back",
};

#[derive(Clone, Copy)]
struct ModulePlaybook {
    run: &'static str,
    needs: &'static str,
    output: &'static str,
    inspect: &'static str,
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
    lines.push(transcript_line(
        "run .",
        &fit(&resolution, width as usize),
        false,
    ));
    lines.push(transcript_line(
        "tool",
        &fit(playbook.run, width as usize),
        false,
    ));
    lines.push(transcript_line(
        "needs",
        &fit(playbook.needs, width as usize),
        false,
    ));
    lines.push(transcript_line(
        "output",
        &fit(playbook.output, width as usize),
        false,
    ));
}

fn run_resolution(primary_tool: &str) -> String {
    if primary_tool == "no-tool" {
        return "run . has no target because this module exposes no shell tool".to_string();
    }
    format!(
        "run . -> {primary_tool} (shell); terminal: kuzushi --target . run {primary_tool} --input '{{}}'"
    )
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
