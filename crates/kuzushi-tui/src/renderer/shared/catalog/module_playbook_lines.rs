use super::*;

pub(crate) fn module_playbook_lines(
    module_id: &str,
    primary_tool: &str,
    width: u16,
) -> Vec<Line<'static>> {
    let mut lines = vec![divider("NEXT", width)];
    let (run, needs, output, inspect) = match module_id {
        "context" => (
            "context build or run . writes .kuzushi/context-snapshot.json",
            "target workspace",
            ".kuzushi/context-snapshot.json",
            "context status · context regen repo",
        ),
        "recon" => (
            "run nmap, subdomain, or http-fingerprint with a target",
            "target host or active workspace",
            "recon notes and optional findings",
            "workspace · findings · use threat-model",
        ),
        "threat-model" => (
            "threats regen proposes a STRIDE / DFD patch; run . dispatches threat-model:build",
            "target, context, explicit model",
            ".kuzushi/threat-model.json",
            "threats summary · threats edit · threats regen",
        ),
        "sast" => (
            "scan runs configured scanners; run . dispatches sast:scan",
            "target, scanner/task config",
            ".kuzushi/v2/findings.sqlite3",
            "tasks · findings · use triage",
        ),
        "carlini-threat-hunt" => (
            "run . after threat-model:build to start adversarial actor hunts",
            "target, threat model, explicit model",
            "threat-hunt runs and promoted findings",
            "show trace · findings · use verify",
        ),
        "agentic-sast" => (
            "run . or run agentic-sast:scan starts dataflow and variant hunting agents",
            "target, context, explicit model",
            "agentic traces and promoted findings",
            "findings · show trace · use verify",
        ),
        _ => (
            "run . to dispatch the primary tool for this module",
            "tool-specific options; inspect options .",
            "structured result or artifact when emitted",
            "options . · prompts · tune · back",
        ),
    };
    let resolution = if primary_tool == "no-tool" {
        "run . has no target because this module exposes no shell tool".to_string()
    } else {
        format!("run . -> {primary_tool} (shell); terminal: kuzushi --target . run {primary_tool} --input '{{}}'")
    };
    lines.push(transcript_line(
        "run .",
        &fit(&resolution, width as usize),
        false,
    ));
    lines.push(transcript_line("tool", &fit(run, width as usize), false));
    lines.push(transcript_line("needs", &fit(needs, width as usize), false));
    lines.push(transcript_line(
        "output",
        &fit(output, width as usize),
        false,
    ));
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
    lines
}

pub(crate) fn catalog_module_category(id: &str, kind: ModuleKind) -> &'static str {
    match id {
        "semgrep"
        | "sast"
        | "codeql"
        | "agentic-sast"
        | "carlini-threat-hunt"
        | "secret-scan"
        | "iac-scan"
        | "dep-hygiene"
        | "taint-iris"
        | "taint-iris-next"
        | "systems-hunt"
        | "chrome-rce"
        | "prompt-armor"
        | "vuln-scout"
        | "tob" => "OFFENSE",
        "context" | "context-lite" | "recon" | "threat-model" | "randori" | "x-ray" | "ndiff"
        | "workspace" => "INTEL",
        "triage" | "verify" | "patch" | "findings" => "DEFENSE",
        _ => module_category(kind).0,
    }
}
