use super::*;
use crate::app::SetupEditor;
use crate::ui_view_models::{setup_readiness_model, SetupReadinessRow, SetupReadinessTone};

pub(crate) fn setup_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let model = setup_readiness_model(app);
    let width = area.width as usize;
    let compact = area.width < 72;
    let mut lines = vec![divider("SETUP · READY THE MAP RUN", area.width)];
    if !compact {
        lines.push(muted(&fit(
            "One readiness check. Model and credentials are required only by the selected plan.",
            width,
        )));
        lines.push(blank());
    }
    lines.extend(setup_readiness_lines(app, &model.rows, width, compact));
    lines.extend(setup_editor_lines(app, width));
    lines.push(blank());
    lines.push(setup_summary_line(&model, width));
    lines
}

fn setup_readiness_lines(
    app: &ShellApp,
    rows: &[SetupReadinessRow],
    width: usize,
    compact: bool,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        lines.push(setup_row_line(
            row,
            index == app.router.setup().cursor(),
            width,
            compact,
        ));
        if !compact && row.id == crate::app::SetupRowId::Target {
            lines.extend(setup_target_fact_lines(app, width));
        }
        lines.extend(setup_selected_row_detail(app, row, index, width, compact));
    }
    lines
}

fn setup_selected_row_detail(
    app: &ShellApp,
    row: &SetupReadinessRow,
    index: usize,
    width: usize,
    compact: bool,
) -> Vec<Line<'static>> {
    if index != app.router.setup().cursor() {
        return Vec::new();
    }
    let prefix = if compact { "    why · " } else { "    " };
    let limit = if compact { 2 } else { usize::MAX };
    let detail = compact_setup_detail(row, compact);
    wrap_text(&format!("{prefix}{detail}"), width)
        .into_iter()
        .take(limit)
        .map(|line| muted(&line))
        .collect()
}

fn compact_setup_detail(row: &SetupReadinessRow, compact: bool) -> String {
    if compact && row.id == crate::app::SetupRowId::Target {
        return crate::ui_view_models::compact_target_path(&row.detail);
    }
    row.detail.clone()
}

fn setup_target_fact_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    if app.active_target_facts_loading() {
        return vec![muted("    Inspecting active target...")];
    }
    let Some(facts) = app.active_target_facts() else {
        return Vec::new();
    };
    crate::ui_view_models::target_fact_detail_lines(facts)
        .into_iter()
        .map(|line| muted(&fit(&format!("    {line}"), width)))
        .collect()
}

fn setup_editor_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    if app.router.setup().editor() != Some(SetupEditor::Budget) {
        return Vec::new();
    }
    let mut lines = vec![blank(), setup_budget_editor_line(app, width)];
    if let Some(error) = app.router.setup().budget_error() {
        lines.push(styled(&fit(&format!(" ! {error}"), width), theme::danger()));
    }
    lines
}

fn setup_summary_line(
    model: &crate::ui_view_models::SetupReadinessModel,
    width: usize,
) -> Line<'static> {
    if model.can_start {
        styled(
            &fit(
                &format!(
                    " READY · {} · move to Start Map and press Enter",
                    setup_execution_summary(model),
                ),
                width,
            ),
            theme::success(),
        )
    } else {
        styled(
            &fit(
                " BLOCKED · resolve the first highlighted readiness row",
                width,
            ),
            theme::warn(),
        )
    }
}

/// What committing this plan will actually execute. "0 Map task(s)" reads as a
/// misconfiguration, so an empty-but-ready plan says what it will do instead.
fn setup_execution_summary(model: &crate::ui_view_models::SetupReadinessModel) -> String {
    if model.selected_tasks == 0 {
        return "no task will run · cached Map artifacts reused".to_string();
    }
    let execution = if model.selected_model_tasks == 0 {
        "deterministic/runtime-free · no model or credentials".to_string()
    } else {
        format!("{} model-backed task(s)", model.selected_model_tasks)
    };
    format!("{} Map task(s) · {execution}", model.selected_tasks)
}

fn setup_row_line(
    row: &SetupReadinessRow,
    selected: bool,
    width: usize,
    compact: bool,
) -> Line<'static> {
    let glyph = match row.tone {
        SetupReadinessTone::Ready => "✓",
        SetupReadinessTone::Optional => "·",
        SetupReadinessTone::Blocked => "!",
        SetupReadinessTone::Action => " ",
    };
    let body = if compact {
        format!("{glyph} {:<12} {}", row.label, row.status)
    } else {
        format!("{glyph} {:<14} {:<16}", row.label, row.status)
    };
    selection_band(&body, selected, width)
}

fn setup_budget_editor_line(app: &ShellApp, width: usize) -> Line<'static> {
    let draft = app.router.setup().budget_draft();
    let value = if draft.is_empty() { "<unset>" } else { draft };
    styled(
        &fit(
            &format!(
                " Budget USD: {value}  · type amount · Enter save · Delete unset · Esc cancel"
            ),
            width,
        ),
        theme::accent(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{V2Config, WorkspaceTarget};

    #[test]
    fn setup_projection_stays_readable_at_compact_and_wide_sizes() {
        let target = tempfile::tempdir().unwrap();
        std::fs::write(
            target.path().join("Cargo.toml"),
            "[package]\nname='fixture'\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.open_setup();

        for area in [Rect::new(0, 0, 40, 12), Rect::new(0, 0, 120, 36)] {
            let text = setup_lines(&app, area)
                .into_iter()
                .map(|line| line.to_string())
                .collect::<Vec<_>>()
                .join("\n");
            assert!(text.contains("SETUP"));
            assert!(text.contains("Map plan"));
            assert!(text.contains("Start Map"));
            assert!(!text.contains("組 map"));
            if area.width >= 120 {
                assert!(
                    text.contains("deterministic/runtime-free · no model or credentials"),
                    "{text}"
                );
            }
        }
    }

    #[test]
    fn compact_setup_wraps_the_selected_reason_instead_of_ellipsizing_it() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.open_setup();
        app.router.setup_mut().set_cursor(3);

        let text = setup_lines(&app, Rect::new(0, 0, 40, 12))
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join(" ");

        assert!(text.contains("why · the selected Map plan is"), "{text}");
        assert!(text.contains("deterministic/runtime-free"), "{text}");
        assert!(text.contains("Start Map"), "{text}");
    }

    #[test]
    fn sixty_column_setup_shows_the_selected_target_reason_and_every_row() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.open_setup();
        app.router.setup_mut().set_cursor(0);

        let text = setup_lines(&app, Rect::new(0, 0, 60, 20))
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("why ·"), "{text}");
        let target_name = target.path().file_name().unwrap().to_string_lossy();
        assert!(text.contains(target_name.as_ref()), "{text}");
        for label in [
            "Map plan",
            "Threat model",
            "Model",
            "Credentials",
            "Prompt",
            "Budget",
            "Start Map",
        ] {
            assert!(text.contains(label), "missing {label}: {text}");
        }
    }

    #[test]
    fn selected_start_action_has_one_cursor_marker() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.open_setup();
        app.router.setup_mut().set_cursor(7);

        let text = setup_lines(&app, Rect::new(0, 0, 60, 20))
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("▸   Start Map"), "{text}");
        assert!(!text.contains("▸ ▸ Start Map"), "{text}");
    }

    #[test]
    fn unselected_start_action_does_not_look_selected() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.open_setup();

        let text = setup_lines(&app, Rect::new(0, 0, 60, 20))
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert_eq!(text.matches('▸').count(), 1, "{text}");
    }

    #[test]
    fn a_reusable_map_plan_is_not_announced_as_blocked() {
        let target = tempfile::tempdir().unwrap();
        std::fs::write(
            target.path().join("Cargo.toml"),
            "[package]\nname='fixture'\n",
        )
        .unwrap();
        std::fs::create_dir_all(target.path().join(".kuzushi")).unwrap();
        crate::test_support::write_current_context_snapshot(target.path(), serde_json::json!({}));
        std::fs::write(target.path().join(".kuzushi/entry-points.json"), "{}").unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.open_setup();
        // The plan row reports PROFILING until the target profile lands.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while app.engagement.planning_picker().profile_pending()
            && std::time::Instant::now() < deadline
        {
            app.apply_view_hydration_results();
            std::thread::yield_now();
        }

        let text = setup_lines(&app, Rect::new(0, 0, 120, 36))
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("NOTHING TO RUN"), "{text}");
        assert!(text.contains("cached Map artifacts reused"), "{text}");
        assert!(!text.contains("BLOCKED"), "{text}");
        assert!(!text.contains("0 Map task(s)"), "{text}");
    }

    #[test]
    fn setup_renders_generation_checked_active_target_facts() {
        let target = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(target.path().join("src")).unwrap();
        std::fs::write(
            target.path().join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='0.1.0'\n",
        )
        .unwrap();
        std::fs::write(target.path().join("src/lib.rs"), "pub fn ready() {}\n").unwrap();
        std::fs::write(
            target.path().join("MODULE.bazel"),
            "module(name='fixture')\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.set_shell_view(crate::ShellView::Config);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while app.active_target_facts().is_none() && std::time::Instant::now() < deadline {
            app.apply_target_candidate_discovery_results();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        app.open_setup();

        let text = setup_lines(&app, Rect::new(0, 0, 120, 36))
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("languages: Rust"), "{text}");
        assert!(text.contains("build: Bazel, Cargo"), "{text}");
        assert!(text.contains("prior Kuzushi:"), "{text}");
    }
}
