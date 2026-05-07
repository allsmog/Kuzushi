use super::*;

pub(in crate::renderer) fn catalog_next_hint(app: &ShellApp) -> String {
    if !app.context_view.exists {
        return "Build the context snapshot with `context build` so SAST has structure to walk."
            .to_string();
    }
    let critical_count = app
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    if critical_count > 0 {
        if let Some((alias, _)) = sorted_finding_aliases(&app.findings).into_iter().next() {
            return format!(
                "Drill in: `open {alias}` for the highest-severity finding · `findings` for the list."
            );
        }
    }
    if !app.findings.is_empty() {
        return format!(
            "{} finding(s) waiting · `findings` to triage · `threats regen` for STRIDE refresh.",
            app.findings.len()
        );
    }
    app.first_finding_hint()
}

pub(in crate::renderer) fn catalog_module_row(
    id: &str,
    description: &str,
    focused: bool,
    widths: &[usize],
) -> Line<'static> {
    let id_width = widths.first().copied().unwrap_or(16);
    let description_width = widths.get(1).copied().unwrap_or(24);
    if focused {
        return Line::from(vec![
            Span::styled("▌ ", theme::accent()),
            Span::styled(
                format!(
                    "{}  {}",
                    pad(id, id_width),
                    pad(description, description_width)
                ),
                theme::selection(),
            ),
        ]);
    }
    Line::from(vec![
        Span::raw("  "),
        Span::styled(pad(id, id_width), theme::primary()),
        Span::raw("  "),
        Span::styled(pad(description, description_width), theme::muted()),
    ])
}

pub(in crate::renderer) fn tool_console_row(
    name: &str,
    description: &str,
    headless: bool,
    width: u16,
) -> Line<'static> {
    let status = if headless { "headless" } else { "interactive" };
    let name_width = if width < 80 { 22 } else { 30 };
    let used = 4 + name_width + status.len() + 6;
    Line::from(vec![
        Span::styled(" ⏵ ", theme::subtle()),
        Span::styled(pad(name, name_width), theme::accent()),
        Span::styled(format!(" {status} "), theme::muted()),
        Span::styled(
            fit(description, (width as usize).saturating_sub(used).max(12)),
            theme::primary(),
        ),
    ])
}

pub(in crate::renderer) fn module_playbook_lines(
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

pub(in crate::renderer) fn catalog_module_category(id: &str, kind: ModuleKind) -> &'static str {
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

pub(in crate::renderer) fn module_category(kind: ModuleKind) -> (&'static str, &'static str) {
    match kind {
        ModuleKind::Offense | ModuleKind::Scan => {
            ("OFFENSE", "hunt vulnerabilities and prove exploitability")
        }
        ModuleKind::Intel | ModuleKind::Context | ModuleKind::Workspace => {
            ("INTEL", "map target context and workspace state")
        }
        ModuleKind::Governance | ModuleKind::Config | ModuleKind::Catalog => (
            "GOVERNANCE",
            "configuration, inventory, and operator controls",
        ),
        ModuleKind::Defense | ModuleKind::Findings | ModuleKind::Triage => {
            ("DEFENSE", "prioritize, triage, and remediate findings")
        }
        ModuleKind::Internal => ("GOVERNANCE", "internal orchestration"),
    }
}

pub(in crate::renderer) fn module_category_blurb(category: &str) -> (&'static str, &'static str) {
    match category {
        "OFFENSE" => (
            "OFFENSE",
            "find vulnerabilities by scanning code, dependencies, and runtime surface",
        ),
        "INTEL" => (
            "INTEL",
            "build context, recon, and threat model the operator reads first",
        ),
        "GOVERNANCE" => ("GOVERNANCE", "configuration, allowlists, and audit trails"),
        "DEFENSE" => ("DEFENSE", "triage, verify, and patch emitted findings"),
        _ => ("OTHER", "loaded module surfaces"),
    }
}
