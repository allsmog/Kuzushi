//! Design-parity tests for the Claude Design mockup bundle.
//!
//! Run with:
//! `cargo test -p kuzushi-tui --test parity`

use std::{collections::BTreeMap, path::PathBuf, process::Command, sync::OnceLock};

use kuzushi_core::{ToolOptionStore, V2Config};
use kuzushi_tui::{
    render_plain_app, AuthScreenFooter, AuthScreenSnapshot, AuthScreenStatus, BootSplashCheck,
    BootSplashCheckState, BootSplashSnapshot, CommandPaletteFooter, CommandPaletteSnapshot,
    CommandPaletteStatus, ConfigScreenFooter, ConfigScreenSnapshot, ConfigScreenStatus,
    ConfirmDialogFooter, ConfirmDialogSnapshot, ConfirmDialogStatus, ContextScreenFooter,
    ContextScreenSnapshot, ContextScreenStatus, CostScreenFooter, CostScreenSnapshot,
    CostScreenStatus, HealthFooter, HealthSnapshot, HealthStatus, HelpScreenFooter,
    HelpScreenSnapshot, HelpScreenStatus, InterruptionFooter, InterruptionSnapshot,
    InterruptionStatus, InterruptionView, KeymapBindingRow, KeymapFooter, KeymapSection,
    KeymapSnapshot, KeymapStatus, OptionsFilter, OptionsScreenFooter, OptionsScreenSnapshot,
    OptionsScreenStatus, OptionsView, QuitConfirmFooter, QuitConfirmSection, QuitConfirmSnapshot,
    QuitConfirmStatus, SastTasksFooter, SastTasksSnapshot, SastTasksStatus, ShellApp, ShellView,
    ThemePaletteRow, ThemePickerFooter, ThemePickerSnapshot, ThemePickerStatus, ThreatView,
    UpdateAvailableFooter, UpdateAvailableSnapshot, UpdateAvailableStatus,
};
use unicode_width::UnicodeWidthChar;

const SNAPSHOT_WIDTH: usize = 120;

macro_rules! parity_case {
    ($name:ident, $mockup:literal, $setup:expr) => {
        #[test]
        fn $name() {
            assert_parity($mockup, $setup);
        }
    };
}

fn assert_parity(mockup: &str, setup: impl FnOnce(&mut ShellApp)) {
    let mut app = fresh_app();
    setup(&mut app);
    let actual = normalize_text(&render_plain_app(&app, SNAPSHOT_WIDTH));
    let expected = mockup_text(mockup);
    ParityContract::for_mockup(mockup).assert(&expected, &actual);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParityFamily {
    Cockpit,
    Activity,
    Overlay,
    Picker,
    Module,
    Document,
    Plain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParityContract<'a> {
    mockup: &'a str,
    family: ParityFamily,
}

impl<'a> ParityContract<'a> {
    fn for_mockup(mockup: &'a str) -> Self {
        Self {
            mockup,
            family: parity_family(mockup),
        }
    }

    fn assert(self, expected: &str, actual: &str) {
        assert!(!actual.trim().is_empty(), "{} rendered empty", self.mockup);
        assert_width_safe(self.mockup, actual);
        assert_no_broken_values(self.mockup, actual);
        assert_semantic_overlap(self, expected, actual);
        assert_selection_contract(self, expected, actual);
    }
}

fn parity_family(mockup: &str) -> ParityFamily {
    if mockup == "plain-mode.jsx" {
        return ParityFamily::Plain;
    }
    if mockup.contains("findings") || matches!(mockup, "since.jsx" | "export-bundle.jsx") {
        return ParityFamily::Cockpit;
    }
    if mockup.contains("running")
        || matches!(
            mockup,
            "tail-stream.jsx" | "pause-resume.jsx" | "triage-queue.jsx"
        )
    {
        return ParityFamily::Activity;
    }
    if is_overlay_mockup(mockup) {
        return ParityFamily::Overlay;
    }
    if matches!(mockup, "onboarding.jsx" | "plan.jsx" | "plan-preview.jsx") {
        return ParityFamily::Picker;
    }
    if is_module_mockup(mockup) {
        return ParityFamily::Module;
    }
    ParityFamily::Document
}

fn is_overlay_mockup(mockup: &str) -> bool {
    matches!(
        mockup,
        "command-palette.jsx"
            | "confirm-dialog.jsx"
            | "quit-confirm.jsx"
            | "theme-picker.jsx"
            | "keymap.jsx"
            | "update-available.jsx"
    ) || mockup.starts_with("err-")
        || mockup.starts_with("budget-")
        || matches!(mockup, "rate-limited.jsx" | "network-down.jsx")
}

fn is_module_mockup(mockup: &str) -> bool {
    const NON_MODULE_PREFIXES: [&str; 13] = [
        "actor", "agent-", "auth", "catalog", "config", "context", "cost", "doctor", "history",
        "kb", "options", "patch", "runs",
    ];
    !NON_MODULE_PREFIXES
        .iter()
        .any(|prefix| mockup.starts_with(prefix))
        && !mockup.starts_with("threats-")
        && !mockup.starts_with("workspace")
}

fn assert_width_safe(mockup: &str, actual: &str) {
    for line in actual.lines() {
        assert!(
            display_width(line) <= SNAPSHOT_WIDTH,
            "{mockup} exceeded {SNAPSHOT_WIDTH} columns: {line:?}"
        );
    }
}

fn assert_no_broken_values(mockup: &str, actual: &str) {
    for broken in ["[object Object]", "undefined", "NaN"] {
        assert!(!actual.contains(broken), "{mockup} rendered {broken}");
    }
}

fn assert_semantic_overlap(contract: ParityContract<'_>, expected: &str, actual: &str) {
    let expected_tokens = semantic_tokens(expected);
    let actual_tokens = semantic_tokens(actual);
    let overlap = expected_tokens.intersection(&actual_tokens).count();
    assert!(
        overlap >= 2,
        "{} {:?} fixture lost Atlas semantics; overlap={overlap}\nactual:\n{actual}",
        contract.mockup,
        contract.family
    );
}

fn semantic_tokens(value: &str) -> std::collections::BTreeSet<String> {
    value
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_')
        .map(str::to_ascii_lowercase)
        .filter(|token| token.len() >= 4 && !SEMANTIC_STOP_WORDS.contains(&token.as_str()))
        .collect()
}

const SEMANTIC_STOP_WORDS: [&str; 12] = [
    "kuzushi", "target", "model", "module", "stage", "enter", "ctrl", "findings", "current",
    "status", "shown", "source",
];

fn assert_selection_contract(contract: ParityContract<'_>, expected: &str, actual: &str) {
    if !selection_critical_mockup(contract.mockup) || !expected.contains('▌') {
        return;
    }
    assert!(
        ['▌', '▸', '>']
            .iter()
            .any(|marker| actual.contains(*marker)),
        "{} lost its non-color selection marker",
        contract.mockup
    );
}

fn selection_critical_mockup(mockup: &str) -> bool {
    matches!(
        mockup,
        "command-palette.jsx"
            | "findings.jsx"
            | "modules.jsx"
            | "theme-picker.jsx"
            | "onboarding.jsx"
    )
}

#[test]
fn parity_target_contains_exactly_114_implement_rows() {
    let target = std::fs::read_to_string(repo_root().join("design/PARITY_TARGET.md"))
        .expect("read parity target");
    let implement_rows = target
        .lines()
        .filter(|line| line.starts_with("| `") && line.contains("| Implement |"))
        .count();
    assert_eq!(implement_rows, 114);
}

fn fresh_app() -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.replace_option_store_for_test(ToolOptionStore::new());
    app
}

fn mockup_text(mockup: &str) -> String {
    let text = mockup_texts()
        .get(mockup)
        .unwrap_or_else(|| panic!("mockup extractor omitted {mockup}"));
    normalize_text(text)
}

fn mockup_texts() -> &'static BTreeMap<String, String> {
    static MOCKUP_TEXTS: OnceLock<Result<BTreeMap<String, String>, String>> = OnceLock::new();
    MOCKUP_TEXTS
        .get_or_init(extract_mockup_texts)
        .as_ref()
        .unwrap_or_else(|error| panic!("{error}"))
}

fn extract_mockup_texts() -> Result<BTreeMap<String, String>, String> {
    let repo = repo_root();
    let output = Command::new("node")
        .arg("scripts/mockup-to-text.mjs")
        .arg("--json")
        .current_dir(&repo)
        .output()
        .map_err(|error| format!("failed to run mockup extractor: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "mockup extractor failed with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("mockup extractor returned invalid JSON: {error}"))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn normalize_text(output: &str) -> String {
    let mut lines = output
        .lines()
        .map(sanitize_for_plain_output)
        .flat_map(width_safe_plain_lines)
        .collect::<Vec<_>>();
    while lines.first().is_some_and(|line| line.trim().is_empty()) {
        lines.remove(0);
    }
    while lines.last().is_some_and(|line| line.trim().is_empty()) {
        lines.pop();
    }
    lines.join("\n")
}

fn width_safe_plain_lines(line: String) -> Vec<String> {
    let trimmed = line.trim_end().to_string();
    if trimmed.chars().count() <= SNAPSHOT_WIDTH {
        return vec![trimmed];
    }
    if should_truncate_plain_line(&trimmed) {
        return vec![fit_plain_line(&trimmed, SNAPSHOT_WIDTH)];
    }
    wrap_plain_line(&trimmed, SNAPSHOT_WIDTH)
}

fn should_truncate_plain_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }
    if line.starts_with("mode:") {
        return true;
    }
    if trimmed.chars().all(|ch| {
        ch == '-' || ch == ' ' || ch == '/' || ch.is_ascii_uppercase() || ch.is_ascii_digit()
    }) {
        return true;
    }

    line.matches("  ").count() >= 3
}

fn fit_plain_line(value: &str, width: usize) -> String {
    if display_width(value) <= width {
        return value.to_string();
    }
    if width <= 3 {
        return take_columns(value, width);
    }
    fit_plain_line_with_ellipsis(value, width)
}

fn fit_plain_line_with_ellipsis(value: &str, width: usize) -> String {
    let budget = width.saturating_sub(3);
    let head = take_columns(value, budget);
    if let Some(clean) = clean_sentence_break(&head, budget) {
        return clean;
    }
    let trimmed = trim_to_word_boundary(&head).trim_end_matches('.');
    format!("{trimmed}...")
}

fn display_width(value: &str) -> usize {
    value
        .chars()
        .map(|ch| UnicodeWidthChar::width(ch).unwrap_or(0))
        .sum()
}

fn take_columns(value: &str, width: usize) -> String {
    let mut out = String::new();
    let mut used = 0usize;
    for ch in value.chars() {
        let next = UnicodeWidthChar::width(ch).unwrap_or(0);
        if used + next > width {
            break;
        }
        out.push(ch);
        used += next;
    }
    out
}

fn clean_sentence_break(head: &str, budget: usize) -> Option<String> {
    let total = head.chars().count();
    if total < 16 {
        return None;
    }
    let min_keep = (budget * 6 / 10).max(1);
    let mut chars_seen = 0usize;
    let mut last_break = None;
    let mut prev = None;
    for (idx, ch) in head.char_indices() {
        chars_seen += 1;
        if matches!(prev, Some('.') | Some('!') | Some('?')) && ch == ' ' && chars_seen > min_keep {
            last_break = Some(idx);
        }
        prev = Some(ch);
    }
    last_break.map(|byte| head[..byte].trim_end().to_string())
}

fn trim_to_word_boundary(head: &str) -> &str {
    let total = head.chars().count();
    if total == 0 {
        return head;
    }
    let min_keep = (total * 7 / 10).max(1);
    last_word_boundary_after(head, min_keep)
        .map(|byte| head[..byte].trim_end_matches([' ', ',']))
        .unwrap_or(head)
}

fn last_word_boundary_after(head: &str, min_keep: usize) -> Option<usize> {
    let mut chars_seen = 0usize;
    let mut boundary = None;
    for (idx, ch) in head.char_indices() {
        chars_seen += 1;
        if matches!(ch, ' ' | '\t' | ',') && chars_seen > min_keep {
            boundary = Some(idx);
        }
    }
    boundary
}

fn wrap_plain_line(value: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![String::new()];
    }
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in value.split_whitespace() {
        push_wrapped_word(&mut lines, &mut current, word, width);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

fn push_wrapped_word(lines: &mut Vec<String>, current: &mut String, word: &str, width: usize) {
    if current.is_empty() {
        *current = word.to_string();
        return;
    }
    if current.chars().count() + 1 + word.chars().count() <= width {
        current.push(' ');
        current.push_str(word);
        return;
    }
    lines.push(std::mem::take(current));
    *current = word.to_string();
}

fn view(app: &mut ShellApp, shell_view: ShellView) {
    app.set_shell_view(shell_view);
}

fn threat_view(app: &mut ShellApp, view: ThreatView) {
    app.open_threat_view_for_test(view);
}

fn patch_view(app: &mut ShellApp, alias: &str) {
    app.open_patch_for_test(alias);
}

fn run_diff_view(app: &mut ShellApp, left: &str, right: &str) {
    app.open_run_diff_for_test(left, right);
}

fn replay_view(app: &mut ShellApp, run_id: &str) {
    app.open_replay_for_test(run_id);
}

fn trace_view(app: &mut ShellApp, run_id: &str) {
    app.open_trace_for_test(run_id);
}

fn interruption_view(app: &mut ShellApp, view: InterruptionView) {
    app.open_interruption_for_test(view);
}

fn module(app: &mut ShellApp, id: &str) {
    app.set_focused_module(Some(id.to_string()));
    app.set_shell_view(ShellView::Module);
}

fn module_run(app: &mut ShellApp, id: &str) {
    app.set_focused_module(Some(id.to_string()));
    app.set_shell_view(ShellView::ModuleRun);
}

fn show_options(app: &mut ShellApp, tool_name: &str) {
    app.open_options_for_test(OptionsView {
        tool_name: tool_name.to_string(),
        filter: OptionsFilter::Standard,
    });
}

fn use_boot_splash_handoff_fixture(app: &mut ShellApp) {
    app.replace_boot_splash_snapshot_for_test(Some(BootSplashSnapshot {
        version_line: "v0.18.2  ·  released 2026-04-29  ·  channel stable".to_string(),
        checks: vec![
            boot_check(
                BootSplashCheckState::Ok,
                "config",
                "~/.kuzushi/v2/options.toml · 12 keys · 3 overridden",
            ),
            boot_check(
                BootSplashCheckState::Ok,
                "audit",
                "~/.kuzushi/v2/audit.log · chain tip cb91…02",
            ),
            boot_check(
                BootSplashCheckState::Ok,
                "workspace",
                "acme-checkout · main@d41a2cc · clean",
            ),
            boot_check(
                BootSplashCheckState::Ok,
                "context-snapshot",
                "fresh · built 11:58 · 482 files · 142 KB",
            ),
            boot_check(
                BootSplashCheckState::Ok,
                "auth · openai",
                "sk-…vQ8R · used 2m ago",
            ),
            boot_check(
                BootSplashCheckState::Ok,
                "auth · anthropic",
                "sk-ant-…pZ12 · used 14h ago",
            ),
            boot_check(
                BootSplashCheckState::Err,
                "auth · github",
                "expired 3d ago · run /auth login github",
            ),
            boot_check(
                BootSplashCheckState::Wait,
                "kb · advisories",
                "… pulling kev + nvd · 41 new",
            ),
            boot_check(
                BootSplashCheckState::Wait,
                "plugins",
                "… enumerating ~/.kuzushi/v2/plugins",
            ),
        ],
        primary_hint:
            "press ? for help · type /catalog for the menu · /doctor if anything looks off"
                .to_string(),
        secondary_hint: "ctrl-c quits · config + history persist across sessions".to_string(),
    }));
}

fn boot_check(
    state: BootSplashCheckState,
    label: &'static str,
    value: &'static str,
) -> BootSplashCheck {
    BootSplashCheck::new(state, label, value)
}

fn use_quit_confirm_handoff_fixture(app: &mut ShellApp) {
    app.replace_quit_confirm_snapshot_for_test(Some(QuitConfirmSnapshot {
        status: QuitConfirmStatus {
            target: "~/work/acme-checkout".to_string(),
            ctx: "fresh".to_string(),
            model: "openai:gpt-4.1".to_string(),
            module: "quit".to_string(),
            cost: "$6.84".to_string(),
        },
        timestamp: "15:59:14".to_string(),
        warning_title: "DON'T LEAVE WORK BEHIND".to_string(),
        warning_body: "you have 3 things in flight that will end the moment kuzushi exits"
            .to_string(),
        sections: quit_confirm_handoff_sections(),
        default_line: "default in 30s ·  Y · checkpoint all + /story + quit".to_string(),
        footer: QuitConfirmFooter {
            stage: "quit · 3 in flight · 2 unstaged · default in 30s".to_string(),
            findings: 38,
            keybinds: vec![
                ("Y".to_string(), "checkpoint+story+quit".to_string()),
                ("y".to_string(), "checkpoint+quit".to_string()),
                ("p".to_string(), "detach".to_string()),
                ("n".to_string(), "cancel".to_string()),
            ],
            prompt_module: "quit".to_string(),
        },
    }));
}

fn quit_confirm_handoff_sections() -> Vec<QuitConfirmSection> {
    vec![
        QuitConfirmSection::new(
            "IN FLIGHT · will be checkpointed if you confirm",
            vec![
                "    ⏵   agentic-sast   r-2118 · frame 41/64 · paused on budget ·  resumable"
                    .to_string(),
                "    ⏵   verify         r-2117 · stage 6/10 · sandbox warm ·  resumable"
                    .to_string(),
                "    ⏵   triage         r-2119 · 7 pending ·  resumable".to_string(),
            ],
        ),
        QuitConfirmSection::new(
            "UNCOMMITTED · operator changes outside kuzushi",
            vec![
                "    !   apps/web/agents/refund-bot.ts  · 14 lines · last touched by you 14:08 ·  not staged"
                    .to_string(),
                "    !   package.json                    · 1 line ·  not staged".to_string(),
            ],
        ),
        QuitConfirmSection::new(
            "NOT YET STORIED · today's significant moments",
            vec![
                "    ▸   F-0012 verified + patched (1h 14m)  ·  threat-model v3 published  ·  budget hard-stop"
                    .to_string(),
                "      /story --audience triage  takes ~ 18s · drafts a memo to share before standup"
                    .to_string(),
            ],
        ),
        QuitConfirmSection::new(
            "CHOOSE",
            vec![
                "    Y   checkpoint all + /story + quit   recommended · ~ 22s · everything resumable next session"
                    .to_string(),
                "    y   checkpoint all + quit             ~ 4s · resumable but no memo".to_string(),
                "    p   keep running in background         detach the TUI · agents continue · kuzushi reattach returns"
                    .to_string(),
                "    a   abort runs + quit                 throws away in-flight work · audit row written"
                    .to_string(),
                "    n   cancel                            stay here".to_string(),
            ],
        ),
    ]
}

fn use_theme_picker_handoff_fixture(app: &mut ShellApp) {
    app.replace_theme_picker_snapshot_for_test(Some(ThemePickerSnapshot {
        status: ThemePickerStatus {
            target: "~/work/acme-checkout".to_string(),
            ctx: "fresh".to_string(),
            model: "openai:gpt-4.1".to_string(),
            module: "theme".to_string(),
            cost: "$0.00".to_string(),
        },
        event_time: "16:08:01".to_string(),
        current_theme: "charcoal".to_string(),
        source_hint: "--from-os".to_string(),
        tty_override_hint: "TERM_PROGRAM=iterm sets charcoal-iterm".to_string(),
        palettes: theme_picker_handoff_palettes(),
        selected_palette: 0,
        preview_title: "charcoal · sample console".to_string(),
        preview_rows: vec![
            "   14:32:14  ●  /scan".to_string(),
            "   14:32:14  ⏵  sast:scan · tasks semgrep, secrets · triage on".to_string(),
            "   14:33:42  ◆  two CRITICALs share a sink — F-0001 · F-0002".to_string(),
            "   14:33:42  ▸  F-0012  ·  CRITICAL  · refund-bot.ts:127".to_string(),
            "   15:46:01  ✗  HARD STOP  · run budget reached".to_string(),
        ],
        accessibility_rows: vec![
            "✓   contrast         all themes ≥ AA on text · high-contrast is AAA on every role"
                .to_string(),
            "✓   color-blind safe severity also encoded as CRIT/HIGH/MED/LOW label · never color-only"
                .to_string(),
            "✓   motion             only progress bars + spinners move · /setg motion off freezes them"
                .to_string(),
            "✓   font-size         /setg ui.font-size 14 · scales the whole TUI".to_string(),
            "·   reader-mode       /setg ui.reader on · linearizes tables for screen readers"
                .to_string(),
        ],
        custom_rows: vec![
            "      /setg theme.from-file ./theme.toml   8-role theme · same shape as built-ins"
                .to_string(),
            "      /show theme --print > my.toml         export the active theme as a starting point"
                .to_string(),
            "      /setg theme charcoal --override accent=#ff7a3d  one-role override".to_string(),
        ],
        flow_time: "16:08:14".to_string(),
        flow_hint: "j/k theme · enter apply (live) · p print sample · Esc close".to_string(),
        footer: ThemePickerFooter {
            stage: "theme · 8 built-in · current charcoal".to_string(),
            findings: 38,
            keybinds: vec![
                ("j/k".to_string(), "theme".to_string()),
                ("enter".to_string(), "apply".to_string()),
                ("p".to_string(), "print sample".to_string()),
                ("Esc".to_string(), "close".to_string()),
            ],
            prompt_module: "theme".to_string(),
        },
    }));
}

fn theme_picker_handoff_palettes() -> Vec<ThemePaletteRow> {
    vec![
        theme_palette(
            "charcoal",
            "#0b0d10",
            "#cfd6e0",
            "#7fb8ff",
            "#e25c5c",
            "default · low-glare on cooler displays",
        ),
        theme_palette(
            "paperwhite",
            "#f6f4ef",
            "#1e2026",
            "#1a4fb2",
            "#a02020",
            "light · printable · review-friendly",
        ),
        theme_palette(
            "high-contrast",
            "#000000",
            "#ffffff",
            "#00ffff",
            "#ff5050",
            "WCAG AAA · all roles ≥ 7:1",
        ),
        theme_palette(
            "solarized-dark",
            "#002b36",
            "#93a1a1",
            "#268bd2",
            "#dc322f",
            "classic · for the loyalists",
        ),
        theme_palette(
            "solarized-light",
            "#fdf6e3",
            "#073642",
            "#268bd2",
            "#dc322f",
            "paired with above for handoff",
        ),
        theme_palette(
            "amber",
            "#1a0f00",
            "#ffb454",
            "#ffe680",
            "#ff7a3d",
            "phosphor · evening operator mode",
        ),
        theme_palette(
            "gruvbox",
            "#1d2021",
            "#ebdbb2",
            "#83a598",
            "#fb4934",
            "warm earth · long-session friendly",
        ),
        theme_palette(
            "tokyo-night",
            "#1a1b26",
            "#a9b1d6",
            "#7aa2f7",
            "#f7768e",
            "familiar to vscode users",
        ),
    ]
}

fn theme_palette(
    name: &'static str,
    background: &'static str,
    foreground: &'static str,
    accent: &'static str,
    severity: &'static str,
    blurb: &'static str,
) -> ThemePaletteRow {
    ThemePaletteRow::new(name, background, foreground, accent, severity, blurb)
}

fn use_keymap_handoff_fixture(app: &mut ShellApp) {
    app.replace_keymap_snapshot_for_test(Some(KeymapSnapshot {
        status: KeymapStatus {
            target: "~/work/acme-checkout".to_string(),
            ctx: "fresh".to_string(),
            model: "openai:gpt-4.1".to_string(),
            module: "help".to_string(),
            cost: "$0.00".to_string(),
        },
        event_time: "16:00:01".to_string(),
        sections: keymap_handoff_sections(),
        note: "every screen's footer is the contract · if a key isn't in the footer, it doesn't do anything on that screen".to_string(),
        footer: KeymapFooter {
            stage: "help · keymap".to_string(),
            findings: 38,
            keybinds: vec![
                ("j/k".to_string(), "row".to_string()),
                ("Esc".to_string(), "close".to_string()),
                ("/keys --print".to_string(), "export".to_string()),
            ],
            prompt_module: "help".to_string(),
        },
    }));
}

fn keymap_handoff_sections() -> Vec<KeymapSection> {
    vec![
        keymap_section(
            "GLOBAL",
            "work everywhere",
            &[
                ("?", "this page"),
                ("Tab", "cycle focus · prompt → list → main → footer"),
                ("Ctrl-C  ·  Ctrl-D", "quit (with confirm if dirty)"),
                (
                    "Ctrl-L",
                    "clear console (keeps state · audit log untouched)",
                ),
                ("Ctrl-P", "command palette · all commands fuzzy-find"),
                ("Ctrl-R", "recall last command · prefix-search history"),
                ("Esc", "cancel field / close overlay / interrupt streaming"),
                (":number", "jump to line in history (e.g. :142 in /tail)"),
            ],
        ),
        keymap_section(
            "NAVIGATION",
            "list views · findings · runs · diffs",
            &[
                ("j  ·  k", "down  ·  up"),
                ("h  ·  l", "collapse  ·  expand"),
                ("g  ·  G", "top  ·  bottom"),
                ("Ctrl-D  ·  Ctrl-U", "half-page down  ·  up"),
                ("enter", "open / drill in"),
                ("o", "open as live trace (for runs / frames)"),
                ("y", "yank · copy id or path under cursor"),
            ],
        ),
        keymap_section(
            "DISPATCH",
            "commands you reach for daily",
            &[
                ("/scan", "sast umbrella · semgrep + secrets + agentic"),
                (
                    "/use <module>",
                    "enter a module · /use sast · /use ndiff cve-…",
                ),
                ("/run <module>", "one-shot a module without entering it"),
                (
                    "/show <kind>",
                    "/show runs · /show options · /show findings · /show kb",
                ),
                ("/set · /setg", "session option · global default"),
                ("/use threat-model", "plan or update v3"),
                (
                    "/use patch <id>",
                    "draft a patch from a finding · staged · operator confirms",
                ),
                (
                    "/use verify <id>",
                    "sandbox-prove a finding · canary in · verdict out",
                ),
            ],
        ),
        keymap_section(
            "LIFECYCLE",
            "pause · resume · checkpoint · revert",
            &[
                (
                    "/pause",
                    "pause active run · checkpoint written · resumable",
                ),
                (
                    "/resume r-…",
                    "resume from last frame · or specific frame with --from",
                ),
                (
                    "/snapshot tag <name>",
                    "manual workspace snapshot · 30d retain",
                ),
                (
                    "/rollback snap-…",
                    "restore · creates snap-now first · reversible",
                ),
                ("/budget", "set or read run/operator/org caps"),
            ],
        ),
        keymap_section(
            "VIEW · this screen",
            "changes per-module · check the footer",
            &[
                ("/?  ·  ?", "show this"),
                ("/keys --module sast", "just the keymap for sast"),
                (
                    "/keys --print",
                    "render a printable cheat-sheet (md → /export)",
                ),
            ],
        ),
    ]
}

fn keymap_section(
    name: &'static str,
    blurb: &'static str,
    rows: &[(&'static str, &'static str)],
) -> KeymapSection {
    KeymapSection::new(
        name,
        blurb,
        rows.iter()
            .map(|(keys, action)| KeymapBindingRow::new(*keys, *action))
            .collect(),
    )
}

fn use_update_available_handoff_fixture(app: &mut ShellApp) {
    app.replace_update_available_snapshot_for_test(Some(UpdateAvailableSnapshot {
        status: UpdateAvailableStatus {
            target: "~/work/acme-checkout".to_string(),
            ctx: "fresh".to_string(),
            model: "openai:gpt-4.1".to_string(),
            module: "—".to_string(),
            cost: "$0.41".to_string(),
        },
        body_rows: update_available_handoff_rows(),
        footer: UpdateAvailableFooter {
            stage: "update available · 0.19.0 · schema v6 → v7".to_string(),
            findings: 38,
            keybinds: vec![
                ("/update".to_string(), "pull".to_string()),
                ("--dry-run".to_string(), "preview".to_string()),
                ("--pin".to_string(), "stay".to_string()),
                ("/changelog".to_string(), "notes".to_string()),
            ],
            prompt_module: None,
        },
    }));
}

fn update_available_handoff_rows() -> Vec<String> {
    vec![
        " 14:43:01  ·  background check · crates.io · release-feed.kuzushi.dev ·  new version"
            .to_string(),
        String::new(),
        update_card_top("UPDATE AVAILABLE"),
        update_card_body(" kuzushi 0.18.2 → 0.19.0  ·  released 2026-05-04  ·  3 days ago"),
        update_card_body(" channel stable  ·  signed by kuzushi-release@trail-of-bits.com"),
        update_card_bottom(),
        String::new(),
        mockup_section_header("HIGHLIGHTS · 0.19.0"),
        "    +   agentic-sast     cross-language taint (py↔ts) by default".to_string(),
        "    +   verify           PoC replay against ephemeral sandbox".to_string(),
        "    +   threat-model     PASTA + STRIDE merged into single tool".to_string(),
        "    Δ   options.toml     migrating · TARGET renamed to WORKSPACE (alias kept until 0.21)"
            .to_string(),
        "    Δ   actors.toml      role redteam renamed to attacker_aux".to_string(),
        "    ✗   removed          --legacy-json (deprecated since 0.16)".to_string(),
        String::new(),
        mockup_section_header("VERSION MISMATCH · this workspace"),
        "   binary             0.18.2".to_string(),
        "   workspace schema   v6      (.kuzushi/v2/schema-version)".to_string(),
        "   binary expects     v6       ✓ compatible".to_string(),
        "   0.19 expects       v7       ! migration on first launch".to_string(),
        "   migration plan     rewrite findings.sqlite3 (38 rows · ~2s)  +  rename TARGET key in options.toml"
            .to_string(),
        String::new(),
        mockup_section_header("OPTIONS"),
        "    1   /update             pull 0.19.0 · auto-migrate · prompt before destructive"
            .to_string(),
        "    2   /update --dry-run   show migration delta without writing".to_string(),
        "    3   /update --pin 0.18.2 stay on this version · suppress checks 7d".to_string(),
        "    4   /changelog         full 0.19.0 notes".to_string(),
        String::new(),
        " 14:43:02  …   note  if you are mid-pentest, --pin is the safe choice".to_string(),
    ]
}

fn update_card_top(title: &str) -> String {
    let label = format!("{title} ");
    format!(
        "   ┌─ {label}{}┐",
        "─".repeat(SNAPSHOT_WIDTH.saturating_sub(6 + label.chars().count()))
    )
}

fn update_card_body(body: &str) -> String {
    format!(
        "   │ {} │",
        fixed_width_for_mockup(body, SNAPSHOT_WIDTH.saturating_sub(8))
    )
}

fn update_card_bottom() -> String {
    format!("   └{}┘", "─".repeat(SNAPSHOT_WIDTH.saturating_sub(6)))
}

fn mockup_section_header(title: &str) -> String {
    let lead = "── ";
    let label = format!("{title} ");
    let used = 1 + lead.chars().count() + label.chars().count();
    let fill = SNAPSHOT_WIDTH.saturating_sub(used).saturating_sub(1).max(1);
    format!(" {lead}{label}{}", "─".repeat(fill))
}

fn fixed_width_for_mockup(value: &str, width: usize) -> String {
    let mut out = value.chars().take(width).collect::<String>();
    out.push_str(&" ".repeat(width.saturating_sub(out.chars().count())));
    out
}

fn use_confirm_dialog_handoff_fixture(app: &mut ShellApp) {
    app.replace_confirm_dialog_snapshot_for_test(Some(ConfirmDialogSnapshot {
        status: ConfirmDialogStatus {
            target: "~/work/acme-checkout".to_string(),
            ctx: "fresh".to_string(),
            model: "openai:gpt-4.1".to_string(),
            module: "sandbox".to_string(),
            cost: "$0.31".to_string(),
        },
        body_rows: confirm_dialog_handoff_rows(),
        footer: ConfirmDialogFooter {
            stage: "pending: 2 confirms · 1 unconditional refusal".to_string(),
            findings: 38,
            keybinds: vec![
                ("y/n".to_string(), "once".to_string()),
                ("Y/N".to_string(), "remember".to_string()),
                ("y -- \"reason\"".to_string(), "annotate".to_string()),
            ],
            prompt_module: None,
        },
    }));
}

fn confirm_dialog_handoff_rows() -> Vec<String> {
    let mut rows = vec![
        " 14:38:01  ◆  agent wants to dispatch sandbox:run curl https://refund.acme/api/internal/balances"
            .to_string(),
        String::new(),
    ];
    rows.extend(confirm_box(
        "CONFIRM · network egress",
        "⚠",
        &[
            " tool          sandbox:run",
            " verb          curl",
            " target        https://refund.acme/api/internal/balances",
            " allowlist     refund.acme is on the project allowlist (matched: refund.acme)",
            " actor         attacker · anthropic:claude-sonnet-4",
            " rationale     \"verify F-0012 reachability — read-only GET, expects 401\"",
            " egress bytes  estimate <2 KB · 1 RTT",
        ],
    ));
    rows.extend([
        String::new(),
        "    y  allow once ·  Y  allow + remember for this run ·  n  deny once ·  N  deny + add to denylist"
            .to_string(),
        String::new(),
    ]);
    rows.extend(confirm_box(
        "REFUSED · destructive verb",
        "✗",
        &[
            " tool          shell:run",
            " verb          rm -rf .git",
            " actor         attacker",
            " rule          destructive verb on host fs · ALWAYS refused",
            " override      none — this gate is unconditional",
        ],
    ));
    rows.push(String::new());
    rows.extend(confirm_box(
        "CONFIRM · fs:write outside .kuzushi/",
        "⚠",
        &[
            " tool          fs:write",
            " path          apps/web/agents/concierge.ts",
            " diff          +6 / -2 lines · same bytes as approved patch F-0002",
            " actor         patcher",
            " rationale     \"applying staged patch · checks 4/5 pass · verify pending\"",
            " undo          .kuzushi/runs/r-2113/snapshots/concierge.ts.bak",
        ],
    ));
    rows.extend([
        String::new(),
        "    i   approvals are recorded in .kuzushi/v2/audit.log · attach reason w/ y -- \"tail of refund spike investigation\""
            .to_string(),
    ]);
    rows
}

fn confirm_box(title: &str, glyph: &str, body: &[&str]) -> Vec<String> {
    let mut rows = vec![confirm_box_top(title, glyph)];
    rows.extend(body.iter().map(|row| confirm_box_body(row)));
    rows.push(confirm_box_bottom());
    rows
}

fn confirm_box_top(title: &str, glyph: &str) -> String {
    let label = format!("{glyph} {title} ");
    let fill = SNAPSHOT_WIDTH
        .saturating_sub(6 + 4 + title.chars().count() + 2)
        .max(1);
    format!("   ┌─ {label}{}┐", "─".repeat(fill))
}

fn confirm_box_body(body: &str) -> String {
    format!(
        "   │ {} │",
        fixed_width_for_mockup(body, SNAPSHOT_WIDTH.saturating_sub(8))
    )
}

fn confirm_box_bottom() -> String {
    format!("   └{}┘", "─".repeat(SNAPSHOT_WIDTH.saturating_sub(6)))
}

fn use_doctor_handoff_fixture(app: &mut ShellApp) {
    app.replace_health_snapshot_for_test(Some(HealthSnapshot {
        status: HealthStatus {
            target: "~/work/acme-checkout".to_string(),
            ctx: "stale (3h)".to_string(),
            model: "openai:gpt-4.1".to_string(),
            module: "doctor".to_string(),
            cost: "$0.00".to_string(),
        },
        body_rows: doctor_handoff_rows(),
        footer: HealthFooter {
            stage: "doctor · 7 ok · 2 warn · 5 fail".to_string(),
            findings: 38,
            keybinds: vec![
                ("/auth".to_string(), "login".to_string()),
                ("/context".to_string(), "build".to_string()),
                ("/config".to_string(), "init".to_string()),
                ("j/k".to_string(), "row".to_string()),
            ],
            prompt_module: None,
        },
    }));
}

fn doctor_handoff_rows() -> Vec<String> {
    vec![
        " 14:55:00  ●  kuzushi doctor --target .".to_string(),
        String::new(),
        mockup_section_header("CONFIG · ~/.kuzushi/v2/config.toml"),
        "   ✓   global config                   12 keys · last edited 2d ago".to_string(),
        "   ✓   project override                .kuzushi/v2/config.toml · 3 keys".to_string(),
        "   ✓   effective model                 openai:gpt-4.1 (env wins over project)"
            .to_string(),
        String::new(),
        mockup_section_header("STATE · .kuzushi/v2/"),
        "   ✓   findings.sqlite3 openable       38 findings · 4 verified · 2 patched"
            .to_string(),
        "   ✓   attachments.json                10 attachments · 8 parsed".to_string(),
        "   ✓   artifact-kb.sqlite3             92 chunks · last index 14:14".to_string(),
        "   !   context-snapshot.json           stale (3h) · run /context build to refresh"
            .to_string(),
        String::new(),
        mockup_section_header("SUBPROCESSES"),
        "   ✓   semgrep                         $PATH · semgrep 1.79.0".to_string(),
        "   ✗   codeql                          NOT FOUND · install or pass {\"binary\":\"…\"}"
            .to_string(),
        "   ✓   nmap                            $PATH · nmap 7.94".to_string(),
        "   ✓   curl                            $PATH · curl 8.4.0".to_string(),
        "   ✓   docker (sandbox)                docker 25.0.3 · daemon up".to_string(),
        String::new(),
        mockup_section_header("AGENT BRIDGE · pi-agent-core"),
        "   ✓   KUZUSHI_AGENT_BRIDGE            /usr/local/bin/pi-agent-bridge".to_string(),
        "   ✓   bridge handshake                37ms · pi-agent-core 0.18.2 · pi-ai 0.4.1"
            .to_string(),
        "   ✓   model channel · openai          gpt-4.1 reachable · 184ms".to_string(),
        "   !   model channel · anthropic       reachable · key expires in 4d".to_string(),
        "   ✗   model channel · google          GOOGLE_API_KEY missing".to_string(),
        String::new(),
        mockup_section_header("PLUGINS"),
        "   ✓   KUZUSHI_SHINSA_PLUGIN           ~/plugins/shinsa · v0.6.2".to_string(),
        "   ✗   KUZUSHI_VULN_SCOUT_PLUGIN       unset · vuln-scout:audit will refuse"
            .to_string(),
        "   ✗   KUZUSHI_TOB_SKILLS_DIR          unset · tob:* will refuse".to_string(),
        "   ✗   KUZUSHI_PROMPT_ARMOR_PLUGIN     unset · prompt-armor:* will refuse"
            .to_string(),
        String::new(),
        " 14:55:01  ◆  7 ok · 2 warn · 5 fail  ·  startup will succeed · runtime tools requiring google, vuln-scout, tob, prompt-armor will refuse explicitly (no fallback model)"
            .to_string(),
    ]
}

fn use_doctor_failing_handoff_fixture(app: &mut ShellApp) {
    app.replace_health_snapshot_for_test(Some(HealthSnapshot {
        status: HealthStatus {
            target: "~/work/acme-checkout".to_string(),
            ctx: "fresh".to_string(),
            model: "openai:gpt-4.1".to_string(),
            module: "doctor".to_string(),
            cost: "$0.00".to_string(),
        },
        body_rows: doctor_failing_handoff_rows(),
        footer: HealthFooter {
            stage: "doctor · 5 fail · 4 warn · 18 ok".to_string(),
            findings: 38,
            keybinds: vec![
                ("--fix".to_string(), "auto".to_string()),
                ("--json".to_string(), "ci".to_string()),
                ("/auth login".to_string(), "remediate".to_string()),
            ],
            prompt_module: Some("doctor".to_string()),
        },
    }));
}

fn doctor_failing_handoff_rows() -> Vec<String> {
    vec![
        " 14:54:01  ●  doctor".to_string(),
        " 14:54:01  ⏵  running 28 checks · 4 lanes · binary · config · models · plugins"
            .to_string(),
        String::new(),
        mockup_section_header("BINARY"),
        "  ✓  kuzushi version               0.18.2".to_string(),
        "  !  channel update                0.19.0 available · 3d         see /update --dry-run"
            .to_string(),
        "  ✓  data dir writable             ~/.kuzushi/v2".to_string(),
        "  ✓  workspace dir writable        .kuzushi/v2".to_string(),
        "  !  free disk                     4.2 GB on /                   < 5 GB · gc may fail"
            .to_string(),
        String::new(),
        mockup_section_header("CONFIG"),
        "  ✓  config schema                 v6 · current".to_string(),
        "  ✓  options.toml parse            12 keys · 3 overridden".to_string(),
        "  !  env override surprises        KUZUSHI_TRIAGE_FLOOR=high     overrides project · acknowledge with /env-allow"
            .to_string(),
        "  ✓  audit log writable            ~/.kuzushi/v2/audit.log".to_string(),
        String::new(),
        mockup_section_header("MODELS"),
        "  ✓  openai key                    sk-…vQ8R · used 2m ago".to_string(),
        "  ✓  anthropic key                 sk-ant-…pZ12 · 14h ago".to_string(),
        "  ✗  github token                  expired 3d ago                run /auth login github · /load gh:* refused"
            .to_string(),
        "  ·  google key                    not configured                optional".to_string(),
        "  ✓  local · ollama                @127.0.0.1:11434              qwen2.5-coder:32b reachable"
            .to_string(),
        "  ✗  role: redteam binding         — · default attacker          rebind via /actor"
            .to_string(),
        String::new(),
        mockup_section_header("PLUGINS · binaries · sandboxes"),
        "  ✗  codeql binary                 not on PATH                   brew install codeql · /run codeql:* refused"
            .to_string(),
        "  ✓  semgrep binary                1.62.0".to_string(),
        "  ✓  firejail                      0.9.72                        sandbox:run will use this"
            .to_string(),
        "  ·  docker                        not installed                 optional · alt sandbox"
            .to_string(),
        "  ✗  tob skills dir                KUZUSHI_TOB_SKILLS_DIR unset  /run tob:* refused"
            .to_string(),
        "  ✗  shinsa plugin                 KUZUSHI_SHINSA_PLUGIN unset   /run shinsa:* refused"
            .to_string(),
        "  !  prompt-armor plugin           ~/plugins/prompt-armor v0.4   older than recommended (v0.6+)"
            .to_string(),
        String::new(),
        mockup_section_header("SUMMARY"),
        "   checks   28    ✓ 18  ! 4  ✗ 5  · 1 skip".to_string(),
        "   blocking 5 · github auth · redteam binding · codeql · tob · shinsa".to_string(),
        "   non-blocking 4 · update available · disk · env override · prompt-armor version"
            .to_string(),
        String::new(),
        " 14:54:09  …  doctor --fix  attempt automatic fix where safe · doctor --json for ci"
            .to_string(),
    ]
}

fn use_no_binary_handoff_fixture(app: &mut ShellApp) {
    app.replace_interruption_snapshot_for_test(Some(InterruptionSnapshot {
        view: InterruptionView::NoBinary,
        status: interruption_status("codeql", "$0.00"),
        body_rows: no_binary_handoff_rows(),
        footer: InterruptionFooter {
            stage: "codeql · refused · binary missing".to_string(),
            findings: 38,
            keybinds: vec![
                ("/setg".to_string(), "persist".to_string()),
                ("/task block".to_string(), "skip".to_string()),
                ("doctor".to_string(), "preflight".to_string()),
                ("/back".to_string(), "catalog".to_string()),
            ],
            prompt_module: Some("codeql".to_string()),
        },
    }));
}

fn no_binary_handoff_rows() -> Vec<String> {
    vec![
        " 13:58:02  ●  /use codeql".to_string(),
        " 13:58:08  ●  /run codeql:scan".to_string(),
        " 13:58:08  ✗   codeql:scan refused  · codeql binary not found".to_string(),
        String::new(),
        mockup_section_header("PROBE"),
        "   which codeql            ✗ not found".to_string(),
        "   CODEQL_HOME             unset".to_string(),
        "   config codeql.binary    unset".to_string(),
        "   ~/.local/bin/codeql     ✗ no such file".to_string(),
        "   ~/codeql/codeql         ✗ no such file".to_string(),
        String::new(),
        mockup_section_header("FIX"),
        "    1   install · brew install codeql  ·  or download from github.com/github/codeql-cli-binaries"
            .to_string(),
        "    2   /run codeql:scan {\"binary\":\"/opt/codeql/codeql\"}   pass per-run"
            .to_string(),
        "    3   /setg codeql.binary /opt/codeql/codeql   persist globally".to_string(),
        "    4   /task block codeql   keep it out of the umbrella entirely".to_string(),
        String::new(),
        "   i   no fallback · kuzushi will not switch you to semgrep without your say-so"
            .to_string(),
        String::new(),
        " 13:58:08  …  doctor for full preflight".to_string(),
    ]
}

fn use_no_model_handoff_fixture(app: &mut ShellApp) {
    app.replace_interruption_snapshot_for_test(Some(InterruptionSnapshot {
        view: InterruptionView::NoModel,
        status: interruption_status("agentic-sast", "$0.00"),
        body_rows: no_model_handoff_rows(),
        footer: InterruptionFooter {
            stage: "agentic-sast · refused · no model".to_string(),
            findings: 38,
            keybinds: vec![
                ("/auth".to_string(), "login".to_string()),
                ("/actor".to_string(), "re-bind".to_string()),
                ("doctor".to_string(), "preflight".to_string()),
                ("/back".to_string(), "catalog".to_string()),
            ],
            prompt_module: Some("agentic-sast".to_string()),
        },
    }));
}

fn no_model_handoff_rows() -> Vec<String> {
    vec![
        " 14:02:18  ●  /use agentic-sast".to_string(),
        " 14:02:24  ●  /run agentic-sast:scan".to_string(),
        " 14:02:24  ✗   agentic-sast:scan refused  · no model configured for role attacker"
            .to_string(),
        String::new(),
        mockup_section_header("WHY"),
        "   role         attacker  binds to anthropic:claude-sonnet-4  (per /actor)"
            .to_string(),
        "   credentials    ✗   ANTHROPIC_API_KEY not set  ·    ✗   ~/.kuzushi/v2/credentials.toml has no anthropic entry"
            .to_string(),
        "   fallback     disabled · kuzushi never silently switches model under you".to_string(),
        String::new(),
        mockup_section_header("FIX"),
        "    1   /auth login anthropic   browser flow · creds saved to credentials.toml"
            .to_string(),
        "    2   /actor attacker model openai:gpt-4.1   re-bind role to a model you do have"
            .to_string(),
        "    3   export ANTHROPIC_API_KEY=sk-ant-…   env-var; precedence over credentials.toml"
            .to_string(),
        String::new(),
        " 14:02:24  …  run doctor for the full preflight  ·  see /auth for provider state"
            .to_string(),
    ]
}

fn use_no_plugin_handoff_fixture(app: &mut ShellApp) {
    app.replace_interruption_snapshot_for_test(Some(InterruptionSnapshot {
        view: InterruptionView::NoPlugin,
        status: interruption_status("tob", "$0.00"),
        body_rows: no_plugin_handoff_rows(),
        footer: InterruptionFooter {
            stage: "tob · refused · plugin missing".to_string(),
            findings: 38,
            keybinds: vec![
                ("doctor".to_string(), "preflight".to_string()),
                ("/modules".to_string(), "status".to_string()),
                ("/back".to_string(), "catalog".to_string()),
            ],
            prompt_module: Some("tob".to_string()),
        },
    }));
}

fn no_plugin_handoff_rows() -> Vec<String> {
    vec![
        " 13:55:31  ●  /use tob".to_string(),
        " 13:55:38  ●  /run tob:audit {\"skill\":\"web-app-pentest\"}".to_string(),
        " 13:55:38  ✗   tob:audit refused  · plugin not configured".to_string(),
        String::new(),
        mockup_section_header("REASON"),
        "   plugin gate    KUZUSHI_TOB_SKILLS_DIR    ✗ unset".to_string(),
        "   expected at    ~/plugins/tob/skills/  ·  contents —".to_string(),
        "   module policy  refuse · tob/* tools depend on operator-supplied skills".to_string(),
        String::new(),
        mockup_section_header("SIMILAR"),
        "    ✗   vuln-scout  KUZUSHI_VULN_SCOUT_PLUGIN unset".to_string(),
        "    ✗   prompt-armor  KUZUSHI_PROMPT_ARMOR_PLUGIN unset".to_string(),
        "    ✓   shinsa       KUZUSHI_SHINSA_PLUGIN ok · ~/plugins/shinsa v0.6.2"
            .to_string(),
        String::new(),
        mockup_section_header("FIX"),
        "    1   install ToB skills:  git clone github.com/trailofbits/audit-skills ~/plugins/tob  then"
            .to_string(),
        "    2   export KUZUSHI_TOB_SKILLS_DIR=~/plugins/tob/skills   (or persist via ~/.kuzushi/v2/env)"
            .to_string(),
        "    3   re-run · /run tob:audit {\"skill\":\"web-app-pentest\"}".to_string(),
        String::new(),
        " 13:55:38  …  doctor enumerates every plugin gate · /modules shows refusing modules"
            .to_string(),
    ]
}

fn use_budget_stop_handoff_fixture(app: &mut ShellApp) {
    app.replace_interruption_snapshot_for_test(Some(InterruptionSnapshot {
        view: InterruptionView::BudgetStop,
        status: interruption_status("agentic-sast", "$2.50"),
        body_rows: budget_stop_handoff_rows(),
        footer: InterruptionFooter {
            stage: "budget · HARD STOP · 41/64 frames · checkpoint saved".to_string(),
            findings: 38,
            keybinds: vec![
                ("y".to_string(), "raise & resume".to_string()),
                ("s".to_string(), "switch actor".to_string()),
                ("n".to_string(), "triage".to_string()),
                ("e".to_string(), "/budget".to_string()),
            ],
            prompt_module: Some("agentic-sast".to_string()),
        },
    }));
}

fn budget_stop_handoff_rows() -> Vec<String> {
    vec![
        " 15:46:01  ⏵   HARD STOP  · run budget reached · r-2118 · agentic-sast halted at frame 41 / 64"
            .to_string(),
        String::new(),
        mockup_section_header("BUDGET"),
        "   this run           [██████████████████████████] $2.50 / $2.50 (100%)"
            .to_string(),
        "   today (operator)   [███████░░░░░░░░░░░░░░░░░░░] $6.84 / $25.00 (27%)"
            .to_string(),
        "   today (org)        [███████░░░░░░░░░░░░░░░░░░░] $142.18 / $500.00 (28%)"
            .to_string(),
        "   this run · time    [████████████████████░░░░░░] $0.78 / $1.00 (78%)"
            .to_string(),
        String::new(),
        mockup_section_header("STATE PRESERVED"),
        "    ✓   checkpoint       written to .kuzushi/runs/r-2118/checkpoint.bin · 2.4 MB"
            .to_string(),
        "    ✓   frames             flushed · 41 entries · audit.log:1856".to_string(),
        "    ✓   partial findings kept 2 candidates (F-0044 medium · F-0045 medium) · pending verify"
            .to_string(),
        "    ·   sandbox            kept warm 30s · then gc".to_string(),
        String::new(),
        mockup_section_header("YOUR OPTIONS"),
        "    1   y raise & resume       raise this run cap to $5 and resume from frame 41"
            .to_string(),
        "    2   Y raise & resume +     same as above + raise today (operator) to $50"
            .to_string(),
        "    3   s switch to cheaper actor   swap attacker to openai:gpt-4.1-mini (~ 6× cheaper) and resume"
            .to_string(),
        "    4   n stop and triage      keep partial findings · /use triage F-0044 · /use triage F-0045"
            .to_string(),
        "    5   e edit budget plan     open /budget  to set per-module / per-run / per-day caps"
            .to_string(),
        String::new(),
        mockup_section_header("WHAT BURNED THE BUDGET"),
        "   actor=attacker  148 calls  1.18M tok in  142k tok out  $2.18   over plan"
            .to_string(),
        "   actor=critic    22 calls   184k tok in   22k tok out   $0.21".to_string(),
        "   actor=triager   0 calls     —             —             $0.00  (scheduled but not yet started)"
            .to_string(),
        "   overhead         11 calls (kb:fetch, fs:read) (free tools)   $0.11"
            .to_string(),
    ]
}

fn use_budget_hard_stop_handoff_fixture(app: &mut ShellApp) {
    app.replace_interruption_snapshot_for_test(Some(InterruptionSnapshot {
        view: InterruptionView::BudgetHardStop,
        status: interruption_status("agentic-sast", "$2.50"),
        body_rows: budget_hard_stop_handoff_rows(),
        footer: InterruptionFooter {
            stage: "budget cap · r-2118 · 118/120 · paused".to_string(),
            findings: 47,
            keybinds: vec![
                ("/run --resume".to_string(), "+$0.50".to_string()),
                ("/budget run".to_string(), "raise".to_string()),
                ("/finalize".to_string(), "best-effort".to_string()),
                ("/abandon".to_string(), "drop wip".to_string()),
            ],
            prompt_module: Some("budget".to_string()),
        },
    }));
}

fn budget_hard_stop_handoff_rows() -> Vec<String> {
    vec![
        " 15:48:01  ⏵  agentic-sast · turn 118 / 120 ·  running".to_string(),
        " 15:48:14  …  cost approaching cap · auto-pause armed at $2.50".to_string(),
        " 15:48:18  ✗   BUDGET CAP HIT  · run paused · 2 turns short of plan".to_string(),
        String::new(),
        "   per-run          [████████████████████████████████████████████████████████████]    $2.50 / $2.50"
            .to_string(),
        "   per-actor (atck) [██████████████████████████████████████░░░░░░░░░░░░░░░░░░░░░░]    $3.18 / $5.00"
            .to_string(),
        "   weekly           [███████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░]   $6.18 / $25.00"
            .to_string(),
        String::new(),
        mockup_section_header("STATE AT PAUSE"),
        "   run             r-2118  module agentic-sast  actor attacker · anthropic:claude-sonnet-4"
            .to_string(),
        "   frame           118 / 120  · 99% of plan complete  ·  2 frames remaining: critic-pass + finalize"
            .to_string(),
        "   findings so far +9 · 1 critical (F-0050), 5 high, 3 medium".to_string(),
        "   dropped          nothing  · run is resumable from frame 118 · checkpoint written"
            .to_string(),
        String::new(),
        mockup_section_header("CHOICES"),
        "    1   /run agentic-sast --resume r-2118 --raise 0.50   +$0.50 · finishes in ~ 30s"
            .to_string(),
        "    2   /budget run 5.00                          raise per-run cap globally · audited"
            .to_string(),
        "    3   /finalize r-2118 --best-effort                  emit findings + memo at frame 118 (skip critic)"
            .to_string(),
        "    4   /abandon r-2118                            keep findings · drop work-in-progress"
            .to_string(),
        String::new(),
        mockup_section_header("CAP POLICY"),
        "   per-run         $2.50 (project)".to_string(),
        "   per-actor       $5.00 (project) · attacker · resets daily".to_string(),
        "   weekly          $25.00 (global)  resets Mon 00:00 UTC".to_string(),
        "   hard?           yes · hits stop the run cleanly · checkpoint always written"
            .to_string(),
        "   soft warning at 75% and 90%".to_string(),
        String::new(),
        "    i   raising the cap  is audited  · cosign required if you cross 2× the configured value"
            .to_string(),
    ]
}

fn use_rate_limited_handoff_fixture(app: &mut ShellApp) {
    app.replace_interruption_snapshot_for_test(Some(InterruptionSnapshot {
        view: InterruptionView::RateLimited,
        status: interruption_status("agentic-sast", "$2.50"),
        body_rows: rate_limited_handoff_rows(),
        footer: InterruptionFooter {
            stage: "rate-limit · 429 · backoff armed · 14s".to_string(),
            findings: 38,
            keybinds: vec![
                ("w".to_string(), "wait".to_string()),
                ("s".to_string(), "switch model".to_string()),
                ("r".to_string(), "route".to_string()),
                ("n".to_string(), "triage".to_string()),
            ],
            prompt_module: Some("agentic-sast".to_string()),
        },
    }));
}

fn rate_limited_handoff_rows() -> Vec<String> {
    vec![
        " 16:04:01  ✗   RATE LIMIT  · anthropic returned 429 · retry-after 14s · this is the 3rd 429 in 5min"
            .to_string(),
        String::new(),
        mockup_section_header("SCOPE · who is affected"),
        "    ⏵   agentic-sast   r-2118 · paused at frame 41/64 ·  resumable".to_string(),
        "    ⏵   chat           streaming response halted at 212/~480 tok ·  resumable"
            .to_string(),
        "    ·   verify         unaffected · sandbox runs locally".to_string(),
        String::new(),
        mockup_section_header("WHY · the 429 in detail"),
        "   header    retry-after: 14s".to_string(),
        "   limit-key input-tokens-per-minute · org acme-llc".to_string(),
        "   used      1.42M / 1.40M cap (101%) ·  over by 21k".to_string(),
        "   cause     attacker actor on r-2118 · 1.18M alone · large fs:read of generated test files (concierge.test.ts × 14)"
            .to_string(),
        String::new(),
        mockup_section_header("AUTOMATIC RESPONSE · already happening"),
        "    ✓   paused both affected runs · checkpointed at frame 41 / 212 tok".to_string(),
        "    ✓   exponential backoff armed · 14s · 28s · 56s · 90s".to_string(),
        "    ✓   audit row written · audit.log:1862 op=llm:rate-limited actor=attacker"
            .to_string(),
        "    ·   budgets       unchanged · this is a temporary network event".to_string(),
        String::new(),
        mockup_section_header("YOUR OPTIONS"),
        "    1   w wait & auto-resume           default · ~ 14s · uses backoff".to_string(),
        "    2   s switch to backup model       openai:gpt-4.1-mini for the rest of these turns · resume after"
            .to_string(),
        "    3   r route per-actor               attacker → openai  ·  critic → anthropic  (mix)"
            .to_string(),
        "    4   e edit budget plan              /budget --tokens 800k/min".to_string(),
        "    5   n stop and triage               keep partial findings, /use triage F-0044"
            .to_string(),
        String::new(),
        "   default in 14s ·  w · wait & auto-resume".to_string(),
    ]
}

fn use_network_down_handoff_fixture(app: &mut ShellApp) {
    app.replace_interruption_snapshot_for_test(Some(InterruptionSnapshot {
        view: InterruptionView::NetworkDown,
        status: InterruptionStatus {
            target: "~/work/acme-checkout".to_string(),
            ctx: "fresh".to_string(),
            model: "openai:gpt-4.1".to_string(),
            module: "—".to_string(),
            cost: "$6.84".to_string(),
        },
        body_rows: network_down_handoff_rows(),
        footer: InterruptionFooter {
            stage: "network · partial · 3 runs paused · default w".to_string(),
            findings: 38,
            keybinds: vec![
                ("w".to_string(), "wait".to_string()),
                ("l".to_string(), "local".to_string()),
                ("p".to_string(), "proxy".to_string()),
                ("d".to_string(), "doctor".to_string()),
                ("n".to_string(), "stop".to_string()),
            ],
            prompt_module: None,
        },
    }));
}

fn network_down_handoff_rows() -> Vec<String> {
    vec![
        " 16:06:01  ✗   NETWORK DOWN  · no route to api.anthropic.com · no route to api.openai.com · localhost models reachable"
            .to_string(),
        String::new(),
        mockup_section_header("REACHABILITY · last 60s"),
        "    ✓   localhost               ollama@127.0.0.1:11434 · 18ms".to_string(),
        "    ✗   api.anthropic.com       timeout (5s) · last 6/6 attempts".to_string(),
        "    ✗   api.openai.com          timeout (5s) · last 6/6 attempts".to_string(),
        "    ✗   share.kuzushi.dev       dns refused".to_string(),
        "    ✓   1.1.1.1                 icmp ok · 9ms".to_string(),
        "    ✗   cloudflare.com (https)  tcp ok · tls handshake fails ·  MITM-ish"
            .to_string(),
        "   verdict partial · icmp + dns to known good ips works · tls broken on outbound api hosts · most likely: captive portal · or corporate tls inspection without ca trust"
            .to_string(),
        String::new(),
        mockup_section_header("AUTOMATIC RESPONSE"),
        "    ✓   paused all model-bound runs · 3 in flight · checkpointed".to_string(),
        "    ✓   switched router to local-only · ollama:llama-3.1-70b · ollama:codestral · cost $0"
            .to_string(),
        "    ✓   flagged actors that need cloud · attacker (carlini class) · downgraded to local-attacker (smaller) if you confirm"
            .to_string(),
        "    ·   audit row audit.log:1864 op=net:lost cause=tls-handshake".to_string(),
        String::new(),
        mockup_section_header("YOUR OPTIONS"),
        "    1   w keep waiting              poll every 10s · auto-resume on first ok"
            .to_string(),
        "    2   l resume on local models    accept downgraded actor · local-attacker · slower · cost $0"
            .to_string(),
        "    3   p edit proxy / ca trust     /setg net.proxy http://corp:3128  ·  /setg net.ca /etc/corp.pem"
            .to_string(),
        "    4   d run /doctor               full reachability + tls trust report".to_string(),
        "    5   n stop                      exit kuzushi · runs are checkpointed".to_string(),
        String::new(),
        "   default in 30s ·  w · keep waiting".to_string(),
    ]
}

fn use_command_palette_handoff_fixture(app: &mut ShellApp) {
    app.replace_command_palette_snapshot_for_test(Some(CommandPaletteSnapshot {
        status: CommandPaletteStatus {
            target: "~/work/acme-checkout".to_string(),
            ctx: "fresh".to_string(),
            model: "openai:gpt-4.1".to_string(),
            module: "palette".to_string(),
            cost: "$0.00".to_string(),
        },
        body_rows: command_palette_handoff_rows(),
        footer: CommandPaletteFooter {
            stage: "palette · \"patch f\" · 14 matches".to_string(),
            findings: 38,
            keybinds: vec![
                ("j/k".to_string(), "match".to_string()),
                ("enter".to_string(), "run".to_string()),
                ("Ctrl-V".to_string(), "edit".to_string()),
                ("Esc".to_string(), "close".to_string()),
            ],
            prompt_module: Some("palette".to_string()),
        },
    }));
}

fn use_config_handoff_fixture(app: &mut ShellApp) {
    app.replace_config_screen_snapshot_for_test(Some(ConfigScreenSnapshot {
        status: ConfigScreenStatus {
            target: "~/work/acme-checkout".to_string(),
            ctx: "fresh".to_string(),
            model: "openai:gpt-4.1".to_string(),
            module: "config".to_string(),
            cost: "$0.00".to_string(),
        },
        body_rows: config_handoff_rows(),
        footer: ConfigScreenFooter {
            stage: "config (read-only)".to_string(),
            findings: 0,
            keybinds: vec![
                ("/set".to_string(), "<k> <v>".to_string()),
                ("/auth".to_string(), "github".to_string()),
                ("/show".to_string(), "audit".to_string()),
                ("/back".to_string(), "catalog".to_string()),
            ],
            prompt_module: Some("config".to_string()),
        },
    }));
}

fn use_context_handoff_fixture(app: &mut ShellApp) {
    app.replace_context_screen_snapshot_for_test(Some(ContextScreenSnapshot {
        status: ContextScreenStatus {
            target: "~/work/acme-checkout".to_string(),
            ctx: "building (8s)".to_string(),
            model: "openai:gpt-4.1".to_string(),
            module: "context".to_string(),
            cost: "$0.00".to_string(),
        },
        body_rows: context_handoff_rows(),
        footer: ContextScreenFooter {
            stage: "context:build (done)".to_string(),
            findings: 0,
            keybinds: vec![
                ("/show".to_string(), "snapshot".to_string()),
                ("/scan".to_string(), "run sast".to_string()),
                ("/back".to_string(), "catalog".to_string()),
                ("?".to_string(), "help".to_string()),
            ],
            prompt_module: Some("context".to_string()),
        },
    }));
}

fn use_auth_handoff_fixture(app: &mut ShellApp) {
    app.replace_auth_screen_snapshot_for_test(Some(AuthScreenSnapshot {
        status: AuthScreenStatus {
            target: "~/work/acme-checkout".to_string(),
            ctx: "fresh".to_string(),
            model: "openai:gpt-4.1".to_string(),
            module: "—".to_string(),
            cost: "$0.00".to_string(),
        },
        body_rows: auth_handoff_rows(),
        footer: AuthScreenFooter {
            stage: "/auth · 3 connected · 1 expired · 1 missing".to_string(),
            findings: 0,
            keybinds: vec![
                ("/auth".to_string(), "login <prov>".to_string()),
                ("/model".to_string(), "<choice>".to_string()),
                ("/cost".to_string(), "spend".to_string()),
                ("/back".to_string(), "catalog".to_string()),
            ],
            prompt_module: None,
        },
    }));
}

fn use_auth_oauth_handoff_fixture(app: &mut ShellApp) {
    app.replace_auth_screen_snapshot_for_test(Some(AuthScreenSnapshot {
        status: AuthScreenStatus {
            target: "~/work/acme-checkout".to_string(),
            ctx: "fresh".to_string(),
            model: "openai:gpt-4.1".to_string(),
            module: "—".to_string(),
            cost: "$0.00".to_string(),
        },
        body_rows: auth_oauth_handoff_rows(),
        footer: AuthScreenFooter {
            stage: "/auth · oauth · waiting on callback · 14.7s".to_string(),
            findings: 38,
            keybinds: vec![
                ("Ctrl+C".to_string(), "cancel".to_string()),
                ("/auth".to_string(), "status state".to_string()),
                ("/auth".to_string(), "logout remove".to_string()),
            ],
            prompt_module: None,
        },
    }));
}

fn use_auth_success_handoff_fixture(app: &mut ShellApp) {
    app.replace_auth_screen_snapshot_for_test(Some(AuthScreenSnapshot {
        status: AuthScreenStatus {
            target: "~/work/acme-checkout".to_string(),
            ctx: "fresh".to_string(),
            model: "openai:gpt-4.1".to_string(),
            module: "—".to_string(),
            cost: "$0.00".to_string(),
        },
        body_rows: auth_success_handoff_rows(),
        footer: AuthScreenFooter {
            stage: "/auth · anthropic ✓ · 6 models".to_string(),
            findings: 38,
            keybinds: vec![
                ("/actor".to_string(), "bind".to_string()),
                ("/model".to_string(), "default".to_string()),
                ("/run".to_string(), "retry".to_string()),
                ("/back".to_string(), "catalog".to_string()),
            ],
            prompt_module: None,
        },
    }));
}

fn use_help_handoff_fixture(app: &mut ShellApp) {
    app.replace_help_screen_snapshot_for_test(Some(HelpScreenSnapshot {
        status: HelpScreenStatus {
            target: "~/work/acme-checkout".to_string(),
            ctx: "fresh".to_string(),
            model: "openai:gpt-4.1".to_string(),
            module: "—".to_string(),
            cost: "$0.00".to_string(),
        },
        body_rows: help_handoff_rows(),
        footer: HelpScreenFooter {
            stage: "help".to_string(),
            findings: 0,
            keybinds: vec![
                ("?<text>".to_string(), "agent chat".to_string()),
                ("Tab".to_string(), "complete".to_string()),
                ("Ctrl+R".to_string(), "search history".to_string()),
                ("/back".to_string(), "catalog".to_string()),
            ],
            prompt_module: None,
        },
    }));
}

fn use_options_handoff_fixture(app: &mut ShellApp) {
    app.replace_options_screen_snapshot_for_test(Some(OptionsScreenSnapshot {
        status: OptionsScreenStatus {
            target: "~/work/acme-checkout".to_string(),
            ctx: "fresh".to_string(),
            model: "openai:gpt-4.1".to_string(),
            module: "sast".to_string(),
            cost: "$0.00".to_string(),
        },
        body_rows: options_handoff_rows(),
        footer: OptionsScreenFooter {
            stage: "/options sast:scan · 1 missing".to_string(),
            findings: 38,
            keybinds: vec![
                ("/set".to_string(), "set value".to_string()),
                ("e".to_string(), "edit json".to_string()),
                ("Tab".to_string(), "complete keys".to_string()),
                ("/run".to_string(), "dispatch".to_string()),
            ],
            prompt_module: Some("sast".to_string()),
        },
    }));
}

fn use_options_set_handoff_fixture(app: &mut ShellApp) {
    app.replace_options_screen_snapshot_for_test(Some(OptionsScreenSnapshot {
        status: OptionsScreenStatus {
            target: "~/work/acme-checkout".to_string(),
            ctx: "fresh".to_string(),
            model: "openai:gpt-4.1".to_string(),
            module: "sast".to_string(),
            cost: "$0.00".to_string(),
        },
        body_rows: options_set_handoff_rows(),
        footer: OptionsScreenFooter {
            stage: "3 pending writes · run + global".to_string(),
            findings: 38,
            keybinds: vec![
                ("y".to_string(), "commit".to_string()),
                ("e".to_string(), "edit".to_string()),
                ("n".to_string(), "discard".to_string()),
                ("/unsetg".to_string(), "clear global".to_string()),
            ],
            prompt_module: Some("sast".to_string()),
        },
    }));
}

fn use_module_options_handoff_fixture(app: &mut ShellApp) {
    app.replace_options_screen_snapshot_for_test(Some(OptionsScreenSnapshot {
        status: OptionsScreenStatus {
            target: "~/work/acme-checkout".to_string(),
            ctx: "fresh".to_string(),
            model: "openai:gpt-4.1".to_string(),
            module: "carlini".to_string(),
            cost: "$0.00".to_string(),
        },
        body_rows: module_options_handoff_rows(),
        footer: OptionsScreenFooter {
            stage: "options · carlini · 12 keys · 3 overridden".to_string(),
            findings: 38,
            keybinds: vec![
                ("/set".to_string(), "run-scope".to_string()),
                ("/setg".to_string(), "global".to_string()),
                ("/unsetg".to_string(), "clear".to_string()),
                ("/run".to_string(), "dispatch".to_string()),
            ],
            prompt_module: Some("carlini".to_string()),
        },
    }));
}

fn use_sast_tasks_handoff_fixture(app: &mut ShellApp) {
    app.replace_sast_tasks_snapshot_for_test(Some(SastTasksSnapshot {
        status: SastTasksStatus {
            target: "~/work/acme-checkout".to_string(),
            ctx: "fresh".to_string(),
            model: "openai:gpt-4.1".to_string(),
            module: "sast".to_string(),
            cost: "$0.00".to_string(),
        },
        body_rows: sast_tasks_handoff_rows(),
        footer: SastTasksFooter {
            stage: "/tasks · 4 active · 2 blocked".to_string(),
            findings: 38,
            keybinds: vec![
                ("j/k".to_string(), "row".to_string()),
                ("a".to_string(), "allow".to_string()),
                ("b".to_string(), "block".to_string()),
                ("/task".to_string(), "reset|mode".to_string()),
            ],
            prompt_module: Some("sast".to_string()),
        },
    }));
}

fn config_handoff_rows() -> Vec<String> {
    vec![
        " 14:05:01  ●  /use config".to_string(),
        " 14:05:06  ●  /show effective".to_string(),
        " 14:05:06  ⏵  merging ~/.kuzushi/config.toml ← ./.kuzushi/config.toml ← env ← flags"
            .to_string(),
        String::new(),
        mockup_section_header("AUTH · 3 providers"),
        "    ✓ openai     sk-…vQ8R  · keychain · last used 2m ago".to_string(),
        "    ✓ anthropic  sk-ant-…pZ12 · keychain · last used 14h ago".to_string(),
        "    ! github     expired 3d ago  · /auth github to refresh".to_string(),
        String::new(),
        mockup_section_header("EFFECTIVE CONFIG · 12 keys"),
        " model.default                   openai:gpt-4.1                      project".to_string(),
        " model.budget.usd                5.00 / run                          user".to_string(),
        " model.routing                   direct                              default".to_string(),
        " triage.auto                     on                                  project".to_string(),
        " triage.severity-floor           medium                              env               KUZUSHI_TRIAGE_FLOOR"
            .to_string(),
        " findings.store                  .kuzushi/v2/findings.sqlite3        default".to_string(),
        " runs.retention                  90d                                 user".to_string(),
        " telemetry                       off                                 project".to_string(),
        " agent.tool.allowlist            grep,read_file,taint-step,write_patcproject"
            .to_string(),
        " agent.tool.network              denied                              project".to_string(),
        " approval.patches                human-required                      project".to_string(),
        " approval.threat-model           human-required                      project".to_string(),
        String::new(),
        mockup_section_header("ALLOWLISTS"),
        "   paths excluded     14 patterns (node_modules, dist, vendor, …)".to_string(),
        "   rules disabled     3 (js/insecure-randomness, rust/unwrap, py/print-debug)"
            .to_string(),
        "   findings suppressed2 (with reason · auto-expire 30d)".to_string(),
        String::new(),
        mockup_section_header("AUDIT TRAIL · last 6 mutations"),
        "   2026-05-06 09:11  jen.t  set triage.severity-floor → medium  (config:edit)"
            .to_string(),
        "   2026-05-05 16:42  jen.t  applied threat-model v3                (threat-model:apply)"
            .to_string(),
        "   2026-05-05 14:18  avi.k  suppressed F-0009 · \"tracking via cdn\" (findings:suppress)"
            .to_string(),
        "   2026-05-04 11:02  jen.t  rotated openai key                     (auth:rotate)"
            .to_string(),
        "   2026-05-04 09:18  avi.k  added rule disable js/insecure-rand    (config:edit)"
            .to_string(),
        "   2026-05-03 17:55  avi.k  patch applied F-0007 · csrf            (patch:apply)"
            .to_string(),
        String::new(),
        " 14:05:08  ·  edit a key with /set <key> <value> · audit log at .kuzushi/v2/audit.log"
            .to_string(),
    ]
}

fn use_cost_handoff_fixture(app: &mut ShellApp) {
    app.replace_cost_screen_snapshot_for_test(Some(CostScreenSnapshot {
        status: CostScreenStatus {
            target: "~/work/acme-checkout".to_string(),
            ctx: "fresh".to_string(),
            model: "openai:gpt-4.1".to_string(),
            module: "—".to_string(),
            cost: "$1.42".to_string(),
        },
        body_rows: cost_handoff_rows(),
        footer: CostScreenFooter {
            stage: "/cost · today $1.42 / $5.00 · this week $6.18 / $25.00".to_string(),
            findings: 38,
            keybinds: vec![
                ("j/k".to_string(), "row".to_string()),
                ("/set".to_string(), "budget.* adjust".to_string()),
                ("/auth".to_string(), "providers".to_string()),
                ("/back".to_string(), "catalog".to_string()),
            ],
            prompt_module: None,
        },
    }));
}

fn use_cost_breakdown_handoff_fixture(app: &mut ShellApp) {
    app.replace_cost_screen_snapshot_for_test(Some(CostScreenSnapshot {
        status: CostScreenStatus {
            target: "~/work/acme-checkout".to_string(),
            ctx: "fresh".to_string(),
            model: "openai:gpt-4.1".to_string(),
            module: "cost".to_string(),
            cost: "$6.18".to_string(),
        },
        body_rows: cost_breakdown_handoff_rows(),
        footer: CostScreenFooter {
            stage: "cost · 8 actors · 7d · $6.18 / $25".to_string(),
            findings: 38,
            keybinds: vec![
                ("--by".to_string(), "actor|module|day".to_string()),
                ("--csv".to_string(), "export".to_string()),
                ("/budget".to_string(), "set".to_string()),
            ],
            prompt_module: Some("cost".to_string()),
        },
    }));
}

fn cost_handoff_rows() -> Vec<String> {
    vec![
        " 14:48:00  ●  /cost".to_string(),
        String::new(),
        mockup_section_header("BUDGETS"),
        "   today              [█████████░░░░░░░░░░░░░░░░░░░░░]    $1.42 /    $5.00   28%"
            .to_string(),
        "   this week          [███████░░░░░░░░░░░░░░░░░░░░░░░]    $6.18 /   $25.00   25%"
            .to_string(),
        "   this month         [██████░░░░░░░░░░░░░░░░░░░░░░░░]   $21.40 /  $100.00   21%"
            .to_string(),
        "   this run           [██░░░░░░░░░░░░░░░░░░░░░░░░░░░░]    $0.41 /    $5.00    8%"
            .to_string(),
        "   agentic-sast       [█████████████████████████░░░░░]    $4.18 /    $5.00   84%"
            .to_string(),
        String::new(),
        mockup_section_header("BY MODULE · last 7 days"),
        "    module                calls   tok in        tok out       cost".to_string(),
        format!("    {}", "─".repeat(116)),
        "    agentic-sast          94      8.4M          912K             $4.18".to_string(),
        "  ▌ carlini-threat-hunt   22      3.1M          241K             $1.94".to_string(),
        "    threat-model          14      612K          188K             $0.84".to_string(),
        "    randori               8       418K          94K              $0.62".to_string(),
        "    taint-iris-next       11      892K          64K              $0.58".to_string(),
        "    shinsa                6       301K          88K              $0.41".to_string(),
        "    prompt-armor          12      218K          54K              $0.38".to_string(),
        "    verify                24      188K          24K              $0.21".to_string(),
        "    patch                 8       94K           32K              $0.14".to_string(),
        "    triage                38      141K          12K              $0.10".to_string(),
        String::new(),
        " 14:48:01  ◆  agentic-sast is at 83% of its module budget — /set budget.agentic-sast 8.00 to extend, or it will halt at $5.00"
            .to_string(),
    ]
}

fn cost_breakdown_handoff_rows() -> Vec<String> {
    vec![
        " 15:02:01  ●  /cost --by actor --since week".to_string(),
        String::new(),
        "  total $ 6.18   budget $ 25.00   remaining $ 18.82   resets Mon 00:00 UTC"
            .to_string(),
        String::new(),
        " actor       model                           calls in        out       $         share"
            .to_string(),
        format!(" {}", "─".repeat(118)),
        " attacker    anthropic:claude-sonnet-4       248   2.41M     184k      $3.18     [███████░░░░░░░] 51%"
            .to_string(),
        " planner     openai:gpt-4.1                  82    0.62M     88k       $0.92     [██░░░░░░░░░░░░] 15%"
            .to_string(),
        " patcher     anthropic:claude-sonnet-4       41    0.41M     52k       $0.78     [██░░░░░░░░░░░░] 13%"
            .to_string(),
        " triager     openai:gpt-4.1-mini             612   1.18M     142k      $0.61     [█░░░░░░░░░░░░░] 10%"
            .to_string(),
        " defender    openai:gpt-4.1                  94    0.41M     38k       $0.42     [█░░░░░░░░░░░░░] 7%"
            .to_string(),
        " verifier    openai:gpt-4.1                  22    0.18M     12k       $0.18     [░░░░░░░░░░░░░░] 3%"
            .to_string(),
        " narrator    anthropic:claude-haiku          18    0.21M     14k       $0.07     [░░░░░░░░░░░░░░] 1%"
            .to_string(),
        " redteam     — · default attacker            0     —         —         $0.00     [░░░░░░░░░░░░░░] 0%"
            .to_string(),
        String::new(),
        mockup_section_header("TOP MODULES · drives the spend"),
        "   agentic-sast   $2.18  +58 mins   128 calls   F-0019, F-0027, F-0034"
            .to_string(),
        "   carlini        $1.41  +27 mins   148 calls   F-0012".to_string(),
        "   threat-model   $0.92  +18 mins   14 calls   v3 model".to_string(),
        "   patch          $0.78  +11 mins   41 calls   F-0002, F-0007".to_string(),
        "   triage         $0.61  +22 mins   612 calls   high-volume classify".to_string(),
        String::new(),
        " 15:02:01  …  /cost --by module · --by day · --by run · --csv > /tmp/spend.csv"
            .to_string(),
    ]
}

fn context_handoff_rows() -> Vec<String> {
    vec![
        " 14:02:11  ●  /use context".to_string(),
        " 14:02:11  ✓  focused module context · primary tool context:build".to_string(),
        " 14:02:18  ●  /run build".to_string(),
        " 14:02:18  ⏵  context:build indexing ~/work/acme-checkout …".to_string(),
        " 14:02:19  …  walking working tree (gitignore + .kuzushiignore honored)".to_string(),
        " 14:02:21  …  classifying languages · routing parsers".to_string(),
        " 14:02:24  …  extracting routes, env reads, sql sites, http calls".to_string(),
        mockup_section_header("SNAPSHOT"),
        "   files       1,284  total · 612 indexed · 38 skipped (binary, vendored)".to_string(),
        "   languages   typescript 58% · rust 21% · python 11% · sql 4% · other 6%".to_string(),
        "   entrypoints apps/web/server.ts · apps/api/main.rs · jobs/worker.py".to_string(),
        "   routes      41 http · 7 grpc · 12 cron".to_string(),
        "   secrets†     0 plaintext, 4 env-templated".to_string(),
        "   sinks       sql:23 · shell:6 · http:51 · fs:18".to_string(),
        "   sources     http body:41 · cookies:9 · headers:12 · cli args:5".to_string(),
        String::new(),
        " 14:02:31  ✓  wrote .kuzushi/context-snapshot.json (184 KB)".to_string(),
        " 14:02:31  ◆  fresh context — sast and threat-model are now both safe to run".to_string(),
        " 14:02:31  ·  next: /scan  ·  /use threat-model  ·  /show snapshot".to_string(),
        String::new(),
    ]
}

fn auth_handoff_rows() -> Vec<String> {
    vec![
        " 14:08:08  ●  /auth".to_string(),
        String::new(),
        mockup_section_header("PROVIDERS · 5"),
        "  ✓  openai      connected  sk-…vQ8R          last 2m ago       gpt-4.1, gpt-4o, o1, o3-mini"
            .to_string(),
        "  ✓  anthropic   connected  sk-ant-…pZ12      last 14h ago      claude-3.7-sonnet, claude-haiku"
            .to_string(),
        "  ✗  google      missing   —                 —                 gemini-2.5-pro, gemini-flash"
            .to_string(),
        "  !  github      expired   ghp_…m4Hs         expired 3d        used by /load gh:… and ndiff"
            .to_string(),
        "  ✓  local       connected  ollama@11434      last 1h ago       llama3.1:8b, qwen2.5-coder:32b"
            .to_string(),
        String::new(),
        mockup_section_header("MODEL · effective"),
        "   current   openai:gpt-4.1 · context 128k · routing direct · stop on missing key"
            .to_string(),
        String::new(),
        "   ▌ openai:gpt-4.1                  ctx 128k      $ 0.50/M in · 1.50/M o· active"
            .to_string(),
        "     openai:gpt-4o                   ctx 128k      $ 0.30/M in · 1.20/M o"
            .to_string(),
        "     anthropic:claude-3.7-sonnet     ctx 200k      $ 0.30/M in · 1.50/M o"
            .to_string(),
        "     local:qwen2.5-coder:32b         ctx 32k       $ free (local)".to_string(),
        "      ▸ /model openai:gpt-4o to switch · /backend list to see routes · /cost for spend"
            .to_string(),
        String::new(),
        mockup_section_header("SPEND · since 2026-05-01"),
        "   today     $ 1.42   · 11 calls  · agentic-sast + carlini + threat-model dominate"
            .to_string(),
        "   this week $ 6.18   · budget $25  · 25%".to_string(),
        "   this run  $ 0.00   · —".to_string(),
        String::new(),
        " 14:08:11  ·  /auth login google · /auth login github · /auth rotate openai  (keychain · never echoed)"
            .to_string(),
    ]
}

fn auth_oauth_handoff_rows() -> Vec<String> {
    vec![
        " 14:22:01  ●  /auth login anthropic".to_string(),
        " 14:22:01  ⏵  starting browser flow · listener on 127.0.0.1:53892".to_string(),
        String::new(),
        "   opening https://console.anthropic.com/oauth/authorize?… in your browser".to_string(),
        "   if it does not open, paste the URL above into a browser".to_string(),
        String::new(),
        mockup_section_header("WAITING FOR CALLBACK"),
        "    …   14.7s elapsed · timeout in 45s".to_string(),
        "   device code   NTRT-PVZQ  ·  show in browser if prompted".to_string(),
        "   scopes        models:read, models:invoke, billing:read".to_string(),
        "   store target  macOS keychain · service kuzushi.anthropic".to_string(),
        String::new(),
        mockup_section_header("PARALLEL STATE"),
        "    ✓   openai       sk-…vQ8R     last 2m ago".to_string(),
        "    …   anthropic    awaiting auth (this flow)".to_string(),
        "    ✗   google       not configured".to_string(),
        "    !   github       expired 3d ago".to_string(),
        String::new(),
        "    i   press Ctrl+C to cancel · /auth status for state · /auth rotate <prov> to re-auth without removing"
            .to_string(),
        String::new(),
        " 14:22:16  …  if you authenticated as a different account, /auth logout anthropic first"
            .to_string(),
    ]
}

fn auth_success_handoff_rows() -> Vec<String> {
    vec![
        " 14:22:31  ✓  callback received · user jen.t@acme.example · org acme-security"
            .to_string(),
        " 14:22:31  ⏵  verifying token  PASS   probing models:read  PASS".to_string(),
        " 14:22:32  ✓  wrote macOS-keychain://kuzushi.anthropic  ·  redacted in ~/.kuzushi/v2/credentials.toml"
            .to_string(),
        String::new(),
        mockup_section_header("AVAILABLE MODELS · 6"),
        "    ✓ claude-opus-4.5       ctx 200k · 5.00/in 25.00/out".to_string(),
        "    ✓ claude-sonnet-4       ctx 200k · 0.30/in  1.50/out".to_string(),
        "    ✓ claude-3.7-sonnet     ctx 200k · 0.30/in  1.50/out".to_string(),
        "    ✓ claude-haiku          ctx 200k · 0.08/in  0.40/out".to_string(),
        "    ✓ claude-3.5-haiku      ctx 200k · 0.08/in  0.40/out".to_string(),
        "    · claude-2.1 (legacy) ctx 100k · 0.80/in  2.40/out".to_string(),
        String::new(),
        mockup_section_header("NEXT"),
        "    1   /actor attacker model anthropic:claude-sonnet-4   bind attacker role"
            .to_string(),
        "    2   /model anthropic:claude-sonnet-4                 set as session default"
            .to_string(),
        "    3   /run carlini:hunt                              re-run, now possible"
            .to_string(),
        String::new(),
        "    i   rotate any time with /auth rotate anthropic · /auth logout anthropic to revoke locally"
            .to_string(),
        String::new(),
        " 14:22:33  ◆  carlini was previously refusing ·  now possible  · run /run carlini:hunt to retry"
            .to_string(),
    ]
}

fn options_handoff_rows() -> Vec<String> {
    vec![
        " 15:02:14  ●  /options sast:scan --missing".to_string(),
        String::new(),
        "  tool   sast:scan   ·   module sast   ·   typed input SastScanInput".to_string(),
        "  schema apps/kuzushi/native/sast/scan.rs#46".to_string(),
        String::new(),
        mockup_section_header("OPTIONS"),
        "   ✓   paths               [String]          [\"apps/\", \"libs/\"]        paths to scan; default workspace root"
            .to_string(),
        "   ·   tasks               [Task]                                      subset of {semgrep, secret-scan, agentic-sast}"
            .to_string(),
        "   ✓   triage              bool              true                      run triage post-scan"
            .to_string(),
        "   ·   severity_floor      Severity          medium                    drop hits below this severity from output"
            .to_string(),
        "   ✗   scope               Scope                                       one of {workspace, since:<ref>, paths:<…>}"
            .to_string(),
        "   ·   language_hints      [Lang]                                      force language detection"
            .to_string(),
        "   ·   sandbox             Sandbox           docker                    docker | none — sandbox child processes"
            .to_string(),
        "   ·   concurrency         u32               4                         task parallelism"
            .to_string(),
        "   ·   budget              Money?                                      optional cost cap; None ⇒ session budget"
            .to_string(),
        "   ·   timeout_s           u32               900                       hard ceiling"
            .to_string(),
        String::new(),
        mockup_section_header("SOURCES (precedence: env > flag > project > global)"),
        "   global  ~/.kuzushi/v2/config.toml  ·  triage=true, concurrency=4".to_string(),
        "   project .kuzushi/v2/config.toml  ·  paths=[\"apps/\",\"libs/\"]".to_string(),
        "   env     KUZUSHI_SANDBOX=docker".to_string(),
        "   flag    --tasks semgrep,agentic-sast".to_string(),
        String::new(),
        " 15:02:14  ◆  missing required: scope · set with /set scope workspace or /run sast:scan {\"scope\":\"workspace\"}"
            .to_string(),
    ]
}

fn options_set_handoff_rows() -> Vec<String> {
    vec![
        " 14:11:01  ●  /show options sast".to_string(),
        " 14:11:01  ⏵  sast has 14 options · 3 overridden".to_string(),
        String::new(),
        mockup_section_header("OPTIONS · sast"),
        "   TARGET                 ~/work/acme-checkout          project".to_string(),
        "   TASKS                  semgrep,secret-scan,agentic-sast default".to_string(),
        "   TRIAGE                 on                               default".to_string(),
        "   SEVERITY_FLOOR         medium                           env".to_string(),
        "   PARALLELISM            8                                user".to_string(),
        "   TIMEOUT_PER_TASK       600s                             default".to_string(),
        "   PERSIST                on                               default".to_string(),
        "   STORE                  .kuzushi/v2/findings.sqlite3  default".to_string(),
        String::new(),
        " 14:11:42  ●  /set PARALLELISM 16".to_string(),
        " 14:11:54  ●  /set SEVERITY_FLOOR high".to_string(),
        " 14:12:03  ●  /setg triage.auto off".to_string(),
        String::new(),
        mockup_section_header("PENDING WRITES · 3"),
        " sast.PARALLELISM              8                        → 16                       run"
            .to_string(),
        " sast.SEVERITY_FLOOR           medium                   → high                     run"
            .to_string(),
        " triage.auto                   on                       → off                      global".to_string(),
        String::new(),
        "    i   /set is run-scoped · /setg writes ~/.kuzushi/v2/options.toml · /unsetg clears global"
            .to_string(),
        "    !   triage.auto = off will skip the post-scan triage actor on the next /scan"
            .to_string(),
        String::new(),
        " 14:12:03  …  y commit · e edit · n discard · /show options sast --after to dry-run"
            .to_string(),
    ]
}

fn module_options_handoff_rows() -> Vec<String> {
    vec![
        " 14:14:08  ●  /use carlini".to_string(),
        " 14:14:11  ●  /show options".to_string(),
        String::new(),
        "  module carlini  describes Carlini-style adversarial threat hunt  actor attacker  budget $2.50 / run"
            .to_string(),
        String::new(),
        " option                  type    value              scope    description".to_string(),
        format!(" {}", "─".repeat(SNAPSHOT_WIDTH - 2)),
        " TARGET                  path    ~/work/acme-checko project  workspace root".to_string(),
        " THREAT_MODEL            path    auto               default  auto = read .kuzushi/threat-model.json"
            .to_string(),
        " HORIZON                 int     3                  default  planner depth · raise for harder targets"
            .to_string(),
        " FRAMES                  int     64                 user     max agent steps before pause"
            .to_string(),
        " BUDGET                  usd     2.50               user     cost cap · soft pause at 80%"
            .to_string(),
        " PERSIST                 bool    true               default  write findings to .kuzushi/v2/findings.sqlite3"
            .to_string(),
        " SAFE_MODE               bool    true               default  no destructive verbs · no host-fs writes"
            .to_string(),
        " NETWORK                 enum    stub               project  stub | allowlist | open  · stub = mocked targets"
            .to_string(),
        " SANDBOX                 enum    firejail           env      firejail | docker | none".to_string(),
        " SEED                    int     0                  default  0 = nondeterministic; set for repro"
            .to_string(),
        " PROMPT_TUNE             string  a-04 + a-08        run      tunes loaded by /tune"
            .to_string(),
        " NOTES_DIR               path    .kuzushi/notes     default  agent scratchpad".to_string(),
        String::new(),
        mockup_section_header("OVERRIDES · 3"),
        "    run    PROMPT_TUNE = a-04 + a-08  set by /tune load a-04".to_string(),
        "    env    SANDBOX = firejail     from KUZUSHI_SANDBOX".to_string(),
        "    user   FRAMES = 64             ~/.kuzushi/v2/options.toml".to_string(),
        String::new(),
        " 14:14:11  …  /set <opt> <val> for run-scope · /setg for global".to_string(),
    ]
}

fn help_handoff_rows() -> Vec<String> {
    vec![
        " 14:00:08  ●  /help".to_string(),
        String::new(),
        mockup_section_header("NAVIGATE browse modules and tools"),
        " /help, ?                                    show this help".to_string(),
        " /modules · /tools                           list visible native modules / tools".to_string(),
        " /use <module>                               focus a module · prompt becomes kuzushi (mod)>"
            .to_string(),
        " /back                                       pop the focused module".to_string(),
        String::new(),
        mockup_section_header("RUN dispatch tools and scans"),
        " /run <tool> [json] · run . [json]           execute a registered tool with typed input"
            .to_string(),
        " /scan [target]                              native sast umbrella scan".to_string(),
        " /ask <question>, ?text                      explicit agent route — never silent".to_string(),
        " /options [tool] · show missing              inspect typed options · see what's required"
            .to_string(),
        " /set <key> <value> · setg <k> <v>           session / global option overrides"
            .to_string(),
        String::new(),
        mockup_section_header("TASKS control the sast umbrella"),
        " /tasks                                      list current task selection".to_string(),
        " /task block <id> · /task allow <id>         disable / enable a single task"
            .to_string(),
        " /task mode auto|manual|toggle               how the umbrella picks tasks".to_string(),
        " /task reset                                 restore default task set".to_string(),
        String::new(),
        mockup_section_header("CONTEXT & KB workspace + attachments"),
        " /context · /context build                   view or rebuild the snapshot".to_string(),
        " /context status · regen <slice>             check freshness · rebuild a slice"
            .to_string(),
        " /kb [module]                                browse local KB attachments".to_string(),
        " attach <path-or-url> · detach <id>          add / remove attachments".to_string(),
        " reparse <id>                                re-extract content from an attachment".to_string(),
        String::new(),
        mockup_section_header("FINDINGS browse / open / triage"),
        " /findings                                   load persisted findings".to_string(),
        " /open <alias-or-fingerprint>                open a finding by alias e.g. F-0001"
            .to_string(),
        " /show aliases [prefix]                      list deterministic aliases".to_string(),
        " /show runs · /replay <runId>                inspect / step a run".to_string(),
        " /since <git-ref>                            diff-scoped findings since a ref".to_string(),
        String::new(),
        mockup_section_header("THREATS model + diff + ask"),
        " /threats [dfd|stride|stories|scope|summary|1switch threat-model views".to_string(),
        " /threats regen · /threats ask <q>           patch · ask a model question"
            .to_string(),
        String::new(),
        mockup_section_header("SESSION auth, model, history"),
        " /auth · /auth login <provider>              show creds status · log in".to_string(),
        " /provider · /backend · /model [c]           inspect / pick model + provider".to_string(),
        " /cost · /config                             spend so far · effective config".to_string(),
        " /history · /clear · /load <spec>            transcript utilities".to_string(),
        " /pause · /resume [runId]                    control long-running scans".to_string(),
        " /quit, exit, /exit                          leave the shell".to_string(),
        String::new(),
        " 14:00:08  ·  tip: Tab completes commands · Ctrl+R searches history · ?<text> is always agent-chat (never silent dispatch)"
            .to_string(),
    ]
}

fn sast_tasks_handoff_rows() -> Vec<String> {
    vec![
        " 15:03:00  *  /tasks".to_string(),
        String::new(),
        "  module sast  ·  task mode  auto   ·  scope workspace  ·  triage  on".to_string(),
        String::new(),
        mockup_section_header("SELECTION · 6 visible · 4 active"),
        "   +   semgrep                   auto    2.4s    pattern-based SAST · always cheap"
            .to_string(),
        "   +   secret-scan               auto    0.8s    high-precision regex set".to_string(),
        "  #   agentic-sast              auto    ~3min    LLM dataflow + variant hunt — pricey but high-signal"
            .to_string(),
        "   +   triage (post-scan)        auto    ~30s    classifies raw hits, dedupes against existing findings"
            .to_string(),
        "   x   codeql                    manual  —       requires codeql binary (missing) — refusing"
            .to_string(),
        "   x   taint-iris                manual  ~6min   experimental cross-lang taint — opt-in only"
            .to_string(),
        String::new(),
        mockup_section_header("CHANGES THIS SESSION"),
        "   x   block taint-iris   13:27 by avi.k   reason: experimental, want to A/B vs agentic-sast"
            .to_string(),
        "   x   block codeql      13:27 (auto)    reason: codeql binary not on $PATH"
            .to_string(),
        String::new(),
        "15:03:00 … override per task with /task allow <id> · /task block <id> · reset with /task reset · switch mode with /task mode manual"
            .to_string(),
    ]
}

fn command_palette_handoff_rows() -> Vec<String> {
    vec![
        " 16:02:01  *  Ctrl-P".to_string(),
        String::new(),
        "   ›  patch f".to_string(),
        "  matches 14  ·  shown 10  ·  source built-ins · plugins · history".to_string(),
        String::new(),
        mockup_section_header("EXACT"),
        "  # /use patch F-0012             finding · open  critical · refund-bot.ts:127 · same shape as F-0002"
            .to_string(),
        "    /use patch F-0027             finding · verifyhigh · concierge > orca-llm SSRF chain"
            .to_string(),
        "    /use patch F-0034             finding · open  critical · k8s root + privileged · class-fix avail"
            .to_string(),
        "    /use patch S-01               secret · active aws-access-key · history rewrite + .env scrub"
            .to_string(),
        String::new(),
        mockup_section_header("FUZZY"),
        "    /show patch r-2115            run · 14:38     concierge.ts patch · already applied"
            .to_string(),
        "    /findings filter --status patcfindings · scope4 entries · last 24h".to_string(),
        "    /use patch postgres-rs --pin 0dep · upgrade-plCVE-2026-2941 · staged"
            .to_string(),
        "    /options patch                config · currentshow options for the patch module"
            .to_string(),
        "    /run patch --apply-class F-003iac · class-fix fixes F-0034, F-0035, F-0039 in one staged patch"
            .to_string(),
        String::new(),
        mockup_section_header("FROM HISTORY · today"),
        "    /use patch F-0002             history · 15:22 CRITICAL prompt-inj · concierge.ts · + applied"
            .to_string(),
        String::new(),
        mockup_section_header("ACTIONS"),
        "      enter run · Ctrl-V edit before run · Tab complete · Esc close · ? open help for this command"
            .to_string(),
        "      palette is scope-aware · the \"ctx\" column tells you where the suggestion comes from"
            .to_string(),
        String::new(),
        mockup_section_header("TIPS"),
        "      @ prefix to filter only findings   ·   # only kb refs   ·   $ only options   ·   . only files in workspace"
            .to_string(),
        "      ! before a command runs without confirm (refused for write/destructive)".to_string(),
        "      => pipes one suggestion into another · e.g. @F-0012 => /use patch = same as the first row above"
            .to_string(),
    ]
}

fn interruption_status(module: &str, cost: &str) -> InterruptionStatus {
    InterruptionStatus {
        target: "~/work/acme-checkout".to_string(),
        ctx: "fresh".to_string(),
        model: "openai:gpt-4.1".to_string(),
        module: module.to_string(),
        cost: cost.to_string(),
    }
}

fn sanitize_for_plain_output(value: &str) -> String {
    value.chars().map(box_drawing_to_ascii).collect()
}

fn box_drawing_to_ascii(ch: char) -> char {
    match ch {
        '\u{2500}' | '\u{2501}' | '\u{2504}' | '\u{2505}' | '\u{2508}' | '\u{2509}'
        | '\u{254c}' | '\u{254d}' | '\u{2550}' => '-',
        '\u{2502}' | '\u{2503}' | '\u{2506}' | '\u{2507}' | '\u{250a}' | '\u{250b}'
        | '\u{254e}' | '\u{254f}' | '\u{2551}' => '|',
        '\u{2500}'..='\u{257f}' => '+',
        '█' | '▌' | '▐' | '▀' | '▄' | '▁'..='▇' => '#',
        '▶' | '▸' | '➜' | '→' | '⇒' => '>',
        '◀' | '◂' | '←' | '⇐' => '<',
        '●' | '•' | '⠋'..='⣿' => '*',
        '○' | '◦' => 'o',
        '✓' | '✔' => '+',
        '✗' | '✘' | '×' => 'x',
        _ => ch,
    }
}

#[test]
fn committed_module_parity_targets_render_descriptor_details() {
    let cases = [
        ("agentic-sast", "agentic-sast:scan"),
        ("codeql", "codeql:scan"),
        ("dep-hygiene", "dep-hygiene:check"),
        ("iac-scan", "iac-scan:scan"),
        ("ndiff", "ndiff:fetch-cve"),
        ("randori", "randori:pasta"),
        ("recon", "recon:import"),
        ("sast", "sast:scan"),
        ("secret-scan", "secret-scan:scan"),
        ("semgrep", "semgrep:scan"),
        ("shinsa", "shinsa:scan"),
        ("taint-iris-next", "taint-iris-next:dataflow-plan"),
        ("tob", "tob:audit"),
        ("triage", "triage:run"),
        ("variant", "variant:hunt"),
        ("verify", "verify:finding"),
        ("vuln-scout", "vuln-scout:audit"),
        ("x-ray", "x-ray:run"),
    ];

    for (module_id, expected_tool) in cases {
        let mut app = fresh_app();
        module(&mut app, module_id);

        let rendered = render_plain_app(&app, SNAPSHOT_WIDTH);

        assert!(
            rendered.contains("MODULE DETAIL"),
            "{module_id} fell back from module detail: {rendered}"
        );
        assert!(
            rendered.contains(module_id),
            "{module_id} missing from rendered module detail: {rendered}"
        );
        assert!(
            rendered.contains(expected_tool),
            "{expected_tool} missing from {module_id} module detail: {rendered}"
        );
        if rendered.contains("AVAILABILITY") {
            assert!(
                rendered.contains("deferred or gated"),
                "{module_id} availability section did not render deferred/gated status: {rendered}"
            );
        }
    }
}

parity_case!(actor_bind, "actor-bind.jsx", |app| view(
    app,
    ShellView::ActorDetail
));
parity_case!(actor, "actor.jsx", |app| view(app, ShellView::ActorDetail));
parity_case!(agent_chat_stream, "agent-chat-stream.jsx", |app| view(
    app,
    ShellView::AgentChat
));
parity_case!(agent_chat, "agent-chat.jsx", |app| view(
    app,
    ShellView::AgentChat
));
parity_case!(agent_refused, "agent-refused.jsx", |app| view(
    app,
    ShellView::AgentChat
));
parity_case!(agent_router, "agent-router.jsx", |app| view(
    app,
    ShellView::Tools
));
parity_case!(agentic_sast_running, "agentic-sast-running.jsx", |app| {
    module_run(app, "agentic-sast")
});
parity_case!(agentic_sast, "agentic-sast.jsx", |app| module(
    app,
    "agentic-sast"
));
parity_case!(auth_oauth, "auth-oauth.jsx", |app| {
    use_auth_oauth_handoff_fixture(app);
    app.open_auth_method_picker_for_test("anthropic");
});
parity_case!(auth_success, "auth-success.jsx", |app| {
    use_auth_success_handoff_fixture(app);
    view(app, ShellView::Auth)
});
parity_case!(auth, "auth.jsx", |app| {
    use_auth_handoff_fixture(app);
    view(app, ShellView::Auth)
});
parity_case!(boot_splash, "boot-splash.jsx", |app| {
    use_boot_splash_handoff_fixture(app);
    view(app, ShellView::BootSplash)
});
parity_case!(budget_hard_stop, "budget-hard-stop.jsx", |app| {
    use_budget_hard_stop_handoff_fixture(app);
    interruption_view(app, InterruptionView::BudgetHardStop)
});
parity_case!(budget_stop, "budget-stop.jsx", |app| {
    use_budget_stop_handoff_fixture(app);
    interruption_view(app, InterruptionView::BudgetStop)
});
parity_case!(catalog_active, "catalog-active.jsx", |app| view(
    app,
    ShellView::Catalog
));
parity_case!(catalog_recent, "catalog-recent.jsx", |app| view(
    app,
    ShellView::Catalog
));
parity_case!(catalog, "catalog.jsx", |app| view(app, ShellView::Catalog));
parity_case!(codeql, "codeql.jsx", |app| module(app, "codeql"));
parity_case!(command_palette, "command-palette.jsx", |app| {
    use_command_palette_handoff_fixture(app);
    view(app, ShellView::CommandPalette)
});
parity_case!(config, "config.jsx", |app| {
    use_config_handoff_fixture(app);
    view(app, ShellView::Config)
});
parity_case!(confirm_dialog, "confirm-dialog.jsx", |app| {
    use_confirm_dialog_handoff_fixture(app);
    view(app, ShellView::ConfirmDialog)
});
parity_case!(context, "context.jsx", |app| {
    use_context_handoff_fixture(app);
    view(app, ShellView::Context)
});
parity_case!(cost_breakdown, "cost-breakdown.jsx", |app| {
    use_cost_breakdown_handoff_fixture(app);
    view(app, ShellView::Cost)
});
parity_case!(cost, "cost.jsx", |app| {
    use_cost_handoff_fixture(app);
    view(app, ShellView::Cost)
});
parity_case!(dep_hygiene_stale, "dep-hygiene-stale.jsx", |app| {
    module(app, "dep-hygiene")
});
parity_case!(dep_hygiene, "dep-hygiene.jsx", |app| module(
    app,
    "dep-hygiene"
));
parity_case!(dep_upgrade, "dep-upgrade.jsx", |app| module(
    app,
    "dep-hygiene"
));
parity_case!(diff_workspace, "diff-workspace.jsx", |app| {
    run_diff_view(app, "run-a", "run-b")
});
parity_case!(doctor_failing, "doctor-failing.jsx", |app| {
    use_doctor_failing_handoff_fixture(app);
    view(app, ShellView::Health)
});
parity_case!(doctor, "doctor.jsx", |app| {
    use_doctor_handoff_fixture(app);
    view(app, ShellView::Health)
});
parity_case!(empty_states, "empty-states.jsx", |app| view(
    app,
    ShellView::Catalog
));
parity_case!(err_no_binary, "err-no-binary.jsx", |app| {
    use_no_binary_handoff_fixture(app);
    app.set_focused_module(Some("codeql".to_string()));
    interruption_view(app, InterruptionView::NoBinary);
});
parity_case!(err_no_model, "err-no-model.jsx", |app| {
    use_no_model_handoff_fixture(app);
    app.set_focused_module(Some("agentic-sast".to_string()));
    interruption_view(app, InterruptionView::NoModel);
});
parity_case!(err_no_plugin, "err-no-plugin.jsx", |app| {
    use_no_plugin_handoff_fixture(app);
    app.set_focused_module(Some("tob".to_string()));
    interruption_view(app, InterruptionView::NoPlugin);
});
parity_case!(export_bundle, "export-bundle.jsx", |app| view(
    app,
    ShellView::Workspace
));
parity_case!(
    findings_empty_match,
    "findings-empty-match.jsx",
    |app| view(app, ShellView::Workbench)
);
parity_case!(findings_filter, "findings-filter.jsx", |app| view(
    app,
    ShellView::Workbench
));
parity_case!(findings, "findings.jsx", |app| view(
    app,
    ShellView::Workbench
));
parity_case!(help, "help.jsx", |app| {
    use_help_handoff_fixture(app);
    view(app, ShellView::Help)
});
parity_case!(history_search, "history-search.jsx", |app| view(
    app,
    ShellView::History
));
parity_case!(history, "history.jsx", |app| view(app, ShellView::History));
parity_case!(iac_crit, "iac-crit.jsx", |app| module(app, "iac-scan"));
parity_case!(iac_scan_critical, "iac-scan-critical.jsx", |app| module(
    app, "iac-scan"
));
parity_case!(iac_scan, "iac-scan.jsx", |app| module(app, "iac-scan"));
parity_case!(kb_show, "kb-show.jsx", |app| view(
    app,
    ShellView::KnowledgeBase
));
parity_case!(kb, "kb.jsx", |app| view(app, ShellView::KnowledgeBase));
parity_case!(keymap, "keymap.jsx", |app| {
    use_keymap_handoff_fixture(app);
    view(app, ShellView::Keymap)
});
parity_case!(load_gh, "load-gh.jsx", |app| view(app, ShellView::History));
parity_case!(module_options, "module-options.jsx", |app| {
    use_module_options_handoff_fixture(app);
    show_options(app, "sast:scan")
});
parity_case!(modules_detail, "modules-detail.jsx", |app| module(
    app, "sast"
));
parity_case!(modules, "modules.jsx", |app| view(app, ShellView::Catalog));
parity_case!(ndiff_running, "ndiff-running.jsx", |app| module_run(
    app, "ndiff"
));
parity_case!(ndiff, "ndiff.jsx", |app| module(app, "ndiff"));
parity_case!(network_down, "network-down.jsx", |app| {
    use_network_down_handoff_fixture(app);
    interruption_view(app, InterruptionView::NetworkDown)
});
parity_case!(onboarding, "onboarding.jsx", |app| view(
    app,
    ShellView::TargetPicker
));
parity_case!(options_set, "options-set.jsx", |app| {
    use_options_set_handoff_fixture(app);
    show_options(app, "sast:scan")
});
parity_case!(options, "options.jsx", |app| {
    use_options_handoff_fixture(app);
    show_options(app, "sast:scan")
});
parity_case!(patch_applied, "patch-applied.jsx", |app| patch_view(
    app, "F-0001"
));
parity_case!(patch_conflict, "patch-conflict.jsx", |app| patch_view(
    app, "F-0001"
));
parity_case!(patch_review, "patch-review.jsx", |app| patch_view(
    app, "F-0001"
));
parity_case!(patch, "patch.jsx", |app| patch_view(app, "F-0001"));
parity_case!(pause_resume, "pause-resume.jsx", |app| view(
    app,
    ShellView::Activity
));
parity_case!(plain_mode, "plain-mode.jsx", |app| view(
    app,
    ShellView::Home
));
parity_case!(plan_preview, "plan-preview.jsx", |app| view(
    app,
    ShellView::PlanningPicker
));
parity_case!(plan, "plan.jsx", |app| view(app, ShellView::PlanningPicker));
parity_case!(prompt, "prompt.jsx", |app| view(
    app,
    ShellView::PromptsEditor
));
parity_case!(prompts, "prompts.jsx", |app| view(
    app,
    ShellView::PromptsEditor
));
parity_case!(quit_confirm, "quit-confirm.jsx", |app| {
    use_quit_confirm_handoff_fixture(app);
    view(app, ShellView::QuitConfirm)
});
parity_case!(randori, "randori.jsx", |app| module(app, "randori"));
parity_case!(rate_limited, "rate-limited.jsx", |app| {
    use_rate_limited_handoff_fixture(app);
    interruption_view(app, InterruptionView::RateLimited)
});
parity_case!(recon, "recon.jsx", |app| module(app, "recon"));
parity_case!(replay_scrub, "replay-scrub.jsx", |app| {
    replay_view(app, "run-1")
});
parity_case!(replay, "replay.jsx", |app| { replay_view(app, "run-1") });
parity_case!(run_controls, "run-controls.jsx", |app| view(
    app,
    ShellView::Cost
));
parity_case!(run_inspect, "run-inspect.jsx", |app| view(
    app,
    ShellView::Runs
));
parity_case!(runs_list, "runs-list.jsx", |app| view(app, ShellView::Runs));
parity_case!(runs, "runs.jsx", |app| view(app, ShellView::Runs));
parity_case!(sast_running, "sast-running.jsx", |app| module_run(
    app, "sast"
));
parity_case!(sast, "sast.jsx", |app| module(app, "sast"));
parity_case!(secret_scan_hits, "secret-scan-hits.jsx", |app| module(
    app,
    "secret-scan"
));
parity_case!(secret_scan, "secret-scan.jsx", |app| module(
    app,
    "secret-scan"
));
parity_case!(secrets_hits, "secrets-hits.jsx", |app| module(
    app,
    "secret-scan"
));
parity_case!(semgrep, "semgrep.jsx", |app| module(app, "semgrep"));
parity_case!(shinsa, "shinsa.jsx", |app| module(app, "shinsa"));
parity_case!(show_runs, "show-runs.jsx", |app| view(app, ShellView::Runs));
parity_case!(since, "since.jsx", |app| view(app, ShellView::Workbench));
parity_case!(story, "story.jsx", |app| view(app, ShellView::Story));
parity_case!(tail_stream, "tail-stream.jsx", |app| view(
    app,
    ShellView::Logs
));
parity_case!(taint_iris_next, "taint-iris-next.jsx", |app| module(
    app,
    "taint-iris-next"
));
parity_case!(tasks, "tasks.jsx", |app| {
    use_sast_tasks_handoff_fixture(app);
    view(app, ShellView::SastTasks)
});
parity_case!(theme_picker, "theme-picker.jsx", |app| {
    use_theme_picker_handoff_fixture(app);
    view(app, ShellView::ThemePicker)
});
parity_case!(threat_model_diff, "threat-model-diff.jsx", |app| {
    threat_view(app, ThreatView::Summary)
});
parity_case!(threat_model, "threat-model.jsx", |app| threat_view(
    app,
    ThreatView::Summary
));
parity_case!(threats_scope, "threats-scope.jsx", |app| threat_view(
    app,
    ThreatView::Scope
));
parity_case!(threats_stories, "threats-stories.jsx", |app| {
    threat_view(app, ThreatView::Stories)
});
parity_case!(threats_stride, "threats-stride.jsx", |app| threat_view(
    app,
    ThreatView::Stride
));
parity_case!(threats_summary, "threats-summary.jsx", |app| {
    threat_view(app, ThreatView::Summary)
});
parity_case!(tob, "tob.jsx", |app| module(app, "tob"));
parity_case!(tools, "tools.jsx", |app| view(app, ShellView::Tools));
parity_case!(trace, "trace.jsx", |app| { trace_view(app, "run-1") });
parity_case!(triage_queue, "triage-queue.jsx", |app| view(
    app,
    ShellView::Activity
));
parity_case!(triage, "triage.jsx", |app| module(app, "triage"));
parity_case!(tune, "tune.jsx", |app| view(app, ShellView::Tune));
parity_case!(update_available, "update-available.jsx", |app| {
    use_update_available_handoff_fixture(app);
    view(app, ShellView::UpdateAvailable)
});
parity_case!(variant, "variant.jsx", |app| module(app, "variant"));
parity_case!(
    verify_sandbox_spinning,
    "verify-sandbox-spinning.jsx",
    |app| module_run(app, "verify")
);
parity_case!(verify_sandbox, "verify-sandbox.jsx", |app| module_run(
    app, "verify"
));
parity_case!(verify, "verify.jsx", |app| module(app, "verify"));
parity_case!(vuln_scout_audit, "vuln-scout-audit.jsx", |app| module(
    app,
    "vuln-scout"
));
parity_case!(vuln_scout, "vuln-scout.jsx", |app| module(
    app,
    "vuln-scout"
));
parity_case!(workspace_manage, "workspace-manage.jsx", |app| view(
    app,
    ShellView::Workspace
));
parity_case!(workspace, "workspace.jsx", |app| view(
    app,
    ShellView::Workspace
));
parity_case!(x_ray_scanning, "x-ray-scanning.jsx", |app| module_run(
    app, "x-ray"
));
parity_case!(x_ray, "x-ray.jsx", |app| module(app, "x-ray"));
