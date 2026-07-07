use super::{cost_model, format_session_cost};
use crate::theme::{active_theme, ColorDepth};
use crate::{ShellApp, ThemePaletteRow, ThemePickerFooter, ThemePickerSnapshot, ThemePickerStatus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThemePickerModel {
    pub(crate) status: ThemePickerStatus,
    pub(crate) event_time: String,
    pub(crate) current_theme: String,
    pub(crate) source_hint: String,
    pub(crate) tty_override_hint: String,
    pub(crate) palettes: Vec<ThemePaletteRow>,
    pub(crate) selected_palette: usize,
    pub(crate) preview_title: String,
    pub(crate) preview_rows: Vec<String>,
    pub(crate) accessibility_rows: Vec<String>,
    pub(crate) custom_rows: Vec<String>,
    pub(crate) flow_time: String,
    pub(crate) flow_hint: String,
    pub(crate) footer: ThemePickerFooter,
}

pub(crate) fn theme_picker_model(app: &ShellApp) -> ThemePickerModel {
    app.theme_picker_snapshot()
        .cloned()
        .map(ThemePickerModel::from)
        .unwrap_or_else(|| default_theme_picker_model(app))
}

impl From<ThemePickerSnapshot> for ThemePickerModel {
    fn from(snapshot: ThemePickerSnapshot) -> Self {
        Self {
            status: snapshot.status,
            event_time: snapshot.event_time,
            current_theme: snapshot.current_theme,
            source_hint: snapshot.source_hint,
            tty_override_hint: snapshot.tty_override_hint,
            palettes: snapshot.palettes,
            selected_palette: snapshot.selected_palette,
            preview_title: snapshot.preview_title,
            preview_rows: snapshot.preview_rows,
            accessibility_rows: snapshot.accessibility_rows,
            custom_rows: snapshot.custom_rows,
            flow_time: snapshot.flow_time,
            flow_hint: snapshot.flow_hint,
            footer: snapshot.footer,
        }
    }
}

fn default_theme_picker_model(app: &ShellApp) -> ThemePickerModel {
    let config = active_theme();
    let current_theme = active_theme_name(config.high_contrast).to_string();
    let palettes = default_palettes();
    ThemePickerModel {
        status: default_status(app),
        event_time: "--:--:--".to_string(),
        current_theme: current_theme.clone(),
        source_hint: "env/config resolved at startup".to_string(),
        tty_override_hint: format!("color depth {}", color_depth_label(config.color_depth)),
        palettes,
        selected_palette: selected_palette_index(config.high_contrast),
        preview_title: format!("{current_theme} · current terminal sample"),
        preview_rows: default_preview_rows(config.reduced_motion),
        accessibility_rows: default_accessibility_rows(config),
        custom_rows: default_custom_rows(),
        flow_time: "--:--:--".to_string(),
        flow_hint: "theme <name> applies a supported palette · Esc close".to_string(),
        footer: default_footer(app, &current_theme),
    }
}

fn default_status(app: &ShellApp) -> ThemePickerStatus {
    ThemePickerStatus {
        target: app
            .target()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "none".to_string()),
        ctx: "not built".to_string(),
        model: app
            .config()
            .model
            .clone()
            .unwrap_or_else(|| "unconfigured".to_string()),
        module: "theme".to_string(),
        cost: default_cost(app),
    }
}

fn default_cost(app: &ShellApp) -> String {
    cost_model(app)
        .budget_status
        .map(|status| status.cells[1].clone())
        .unwrap_or_else(|| format_session_cost(0.0))
}

fn active_theme_name(high_contrast: bool) -> &'static str {
    if high_contrast {
        "high-contrast"
    } else {
        "default"
    }
}

fn color_depth_label(depth: ColorDepth) -> &'static str {
    match depth {
        ColorDepth::TrueColor => "truecolor",
        ColorDepth::Ansi256 => "ansi256",
        ColorDepth::Ansi16 => "ansi16",
        ColorDepth::None => "none",
    }
}

fn selected_palette_index(high_contrast: bool) -> usize {
    usize::from(high_contrast)
}

fn default_palettes() -> Vec<ThemePaletteRow> {
    vec![
        ThemePaletteRow::new(
            "default",
            "terminal",
            "primary",
            "accent",
            "severity",
            "balanced cockpit palette",
        ),
        ThemePaletteRow::new(
            "high-contrast",
            "terminal",
            "bright",
            "cyan",
            "red",
            "KUZUSHI_THEME=high-contrast",
        ),
        ThemePaletteRow::new(
            "no-color",
            "plain",
            "text",
            "labels",
            "labels",
            "NO_COLOR present · semantic text remains",
        ),
    ]
}

fn default_preview_rows(reduced_motion: bool) -> Vec<String> {
    let spinner = if reduced_motion { "paused" } else { "animated" };
    vec![
        "   --:--:--  ●  /scan".to_string(),
        format!("   --:--:--  ⏵  sast:scan · progress {spinner}"),
        "   --:--:--  ▸  finding rows keep severity labels".to_string(),
        "   --:--:--  ✗  hard stops stay explicit".to_string(),
    ]
}

fn default_accessibility_rows(config: crate::theme::ThemeConfig) -> Vec<String> {
    vec![
        "✓   contrast         high-contrast mode is available for low-contrast terminals"
            .to_string(),
        "✓   color-blind safe severity uses CRIT/HIGH/MED/LOW labels, never color-only".to_string(),
        motion_row(config.reduced_motion),
        format!(
            "·   color-depth      terminal reports {}",
            color_depth_label(config.color_depth)
        ),
        "·   reader-mode       plain output linearizes tables for scripts and screen readers"
            .to_string(),
    ]
}

fn motion_row(reduced_motion: bool) -> String {
    if reduced_motion {
        "✓   motion             reduced motion enabled · spinner advance is paused".to_string()
    } else {
        "✓   motion             progress bars + spinners move · set KUZUSHI_REDUCED_MOTION=1 to pause".to_string()
    }
}

fn default_custom_rows() -> Vec<String> {
    vec![
        "      KUZUSHI_THEME=high-contrast        enable the high-contrast palette".to_string(),
        "      KUZUSHI_REDUCED_MOTION=1           freeze spinner animation".to_string(),
        "      NO_COLOR=1                         strip semantic foreground colors".to_string(),
    ]
}

fn default_footer(app: &ShellApp, current_theme: &str) -> ThemePickerFooter {
    ThemePickerFooter {
        stage: format!("theme · current {current_theme}"),
        findings: app.findings_total_count(),
        keybinds: vec![
            ("theme <name>".to_string(), "apply".to_string()),
            ("Esc".to_string(), "close".to_string()),
        ],
        prompt_module: "theme".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn theme_picker_model_uses_route_owned_snapshot() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.replace_theme_picker_snapshot_for_test(Some(snapshot()));

        let model = theme_picker_model(&app);

        assert_eq!(model.current_theme, "route-theme");
        assert_eq!(model.palettes[0].name, "route");
        assert_eq!(model.footer.prompt_module, "theme-route");
    }

    fn snapshot() -> ThemePickerSnapshot {
        ThemePickerSnapshot {
            status: status(),
            event_time: "12:00:00".to_string(),
            current_theme: "route-theme".to_string(),
            source_hint: "route".to_string(),
            tty_override_hint: "tty".to_string(),
            palettes: vec![ThemePaletteRow::new(
                "route", "bg", "fg", "accent", "sev", "blurb",
            )],
            selected_palette: 0,
            preview_title: "preview".to_string(),
            preview_rows: Vec::new(),
            accessibility_rows: Vec::new(),
            custom_rows: Vec::new(),
            flow_time: "12:00:00".to_string(),
            flow_hint: "hint".to_string(),
            footer: ThemePickerFooter {
                stage: "theme".to_string(),
                findings: 0,
                keybinds: Vec::new(),
                prompt_module: "theme-route".to_string(),
            },
        }
    }

    fn status() -> ThemePickerStatus {
        ThemePickerStatus {
            target: "target".to_string(),
            ctx: "ctx".to_string(),
            model: "model".to_string(),
            module: "theme".to_string(),
            cost: "$0.00".to_string(),
        }
    }
}
