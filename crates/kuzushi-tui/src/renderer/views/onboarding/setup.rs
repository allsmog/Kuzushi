use super::*;
use crate::ui_view_models::{setup_readiness_model, SetupReadinessRow, SetupReadinessTone};

pub(crate) fn setup_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    if app.budget_editor_open() {
        return super::budget_editor::budget_editor_lines(app, area);
    }
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
    lines.push(blank());
    lines.extend(setup_summary_lines(&model, width));
    lines
}

fn setup_readiness_lines(
    app: &ShellApp,
    rows: &[SetupReadinessRow],
    width: usize,
    compact: bool,
) -> Vec<Line<'static>> {
    let cursor = app.router.setup().cursor();
    rows.iter()
        .enumerate()
        .flat_map(|(index, row)| setup_row_lines(app, row, index == cursor, width, compact))
        .collect()
}

/// One readiness row plus what explains it. The Target facts block already
/// leads with the target path, so the selected-row detail — which for Target
/// is that same path — is only shown when no facts block rendered.
fn setup_row_lines(
    app: &ShellApp,
    row: &SetupReadinessRow,
    selected: bool,
    width: usize,
    compact: bool,
) -> Vec<Line<'static>> {
    let mut lines = vec![setup_row_line(row, selected, width, compact)];
    let facts = setup_row_fact_lines(app, row, width, compact);
    let explained_by_facts = !facts.is_empty();
    lines.extend(facts);
    if selected && !explained_by_facts {
        lines.extend(setup_selected_row_detail(row, width, compact));
    }
    lines
}

fn setup_row_fact_lines(
    app: &ShellApp,
    row: &SetupReadinessRow,
    width: usize,
    compact: bool,
) -> Vec<Line<'static>> {
    if compact || row.id != crate::app::SetupRowId::Target {
        return Vec::new();
    }
    setup_target_fact_lines(app, &row.detail, width)
}

fn setup_selected_row_detail(
    row: &SetupReadinessRow,
    width: usize,
    compact: bool,
) -> Vec<Line<'static>> {
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

fn setup_target_fact_lines(app: &ShellApp, path: &str, width: usize) -> Vec<Line<'static>> {
    let facts = if app.active_target_facts_loading() {
        vec!["Inspecting active target...".to_string()]
    } else if let Some(facts) = app.active_target_facts() {
        crate::ui_view_models::target_fact_detail_lines(facts).to_vec()
    } else {
        return Vec::new();
    };
    std::iter::once(path.to_string())
        .chain(facts)
        .map(|line| muted(&fit(&format!("    {line}"), width)))
        .collect()
}

const START_MAP_CALL_TO_ACTION: &str = "move to Start Map and press Enter";

/// The closing verdict for the plan. The execution segments, the call to
/// action, and the expected post-Map recommendation run are each load-bearing
/// and together they overflow one 120-column line, so the summary spends extra
/// lines instead of ellipsizing any of them away.
fn setup_summary_lines(
    model: &crate::ui_view_models::SetupReadinessModel,
    width: usize,
) -> Vec<Line<'static>> {
    if !model.can_start {
        return vec![styled(
            &fit(
                " BLOCKED · resolve the first highlighted readiness row",
                width,
            ),
            theme::warn(),
        )];
    }
    let mut lines = setup_ready_lines(model, width);
    lines.extend(setup_refresh_disclosure_lines(model, width));
    lines
}

/// Keep the verdict and its call to action on one line while they fit, and
/// split them at that seam rather than letting a word wrap orphan the tail.
fn setup_ready_lines(
    model: &crate::ui_view_models::SetupReadinessModel,
    width: usize,
) -> Vec<Line<'static>> {
    let verdict = format!("READY · {}", setup_execution_summary(model));
    let joined = format!("{verdict} · {START_MAP_CALL_TO_ACTION}");
    if display_width(&joined) <= width.saturating_sub(1) {
        return wrapped_lines(&joined, " ", width, theme::success());
    }
    let mut lines = wrapped_lines(&verdict, " ", width, theme::success());
    lines.extend(wrapped_lines(
        START_MAP_CALL_TO_ACTION,
        " ",
        width,
        theme::success(),
    ));
    lines
}

/// Planned tasks are not the whole Map execution envelope: once a non-skipped
/// Map drains, Kuzushi runs one deterministic module-recommendation refresh
/// when the latest run holds no `recommendations.json`.
///
/// That freshness check belongs to the post-Map state, and Setup cannot read it
/// early. Every task the plan runs mints a new run whose summary moves the
/// latest-run pointer, and no Map tool writes `recommendations.json`, so a
/// committed non-empty plan always leaves the post-Map check looking at a run
/// without that artifact — even for a hydrated engagement whose current latest
/// run has a readable one. Judging freshness here would understate the envelope
/// exactly for those cached engagements, so the disclosure follows the plan.
///
/// The plan, not the selection, decides: checked-but-cached rows are reused
/// without running, and an all-reused (or empty) plan never completes Map at
/// all, so neither may promise the refresh. `expected` carries the residual
/// uncertainty — a plan whose tasks all fail stops at the retry gate instead.
fn setup_refresh_disclosure_lines(
    model: &crate::ui_view_models::SetupReadinessModel,
    width: usize,
) -> Vec<Line<'static>> {
    if model.runnable_tasks == 0 || model.selected_model_tasks > 0 {
        return Vec::new();
    }
    wrapped_lines(
        "+1 expected background recommendation run after Map",
        "   ",
        width,
        theme::muted(),
    )
}

/// Wrap `value` under a fixed left indent. Wrapping keeps every segment of the
/// summary readable at narrow widths instead of ellipsizing the tail away.
fn wrapped_lines(value: &str, indent: &str, width: usize, style: Style) -> Vec<Line<'static>> {
    wrap_text(value, width.saturating_sub(indent.chars().count()))
        .into_iter()
        .map(|line| styled(&format!("{indent}{line}"), style))
        .collect()
}

/// What committing this plan will actually execute. "0 Map task(s)" reads as a
/// misconfiguration, so an empty-but-ready plan says what it will do instead.
fn setup_execution_summary(model: &crate::ui_view_models::SetupReadinessModel) -> String {
    if model.selected_tasks == 0 {
        return "no selected Map task will run · cached Map artifacts reused".to_string();
    }

    let execution = if model.selected_model_tasks == 0 {
        "deterministic/runtime-free · no model or credentials".to_string()
    } else {
        format!("{} model-backed task(s)", model.selected_model_tasks)
    };
    format!(
        "{} selected Map task(s) · {execution}",
        model.selected_tasks
    )
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
                assert!(
                    text.contains("+1 expected background recommendation run"),
                    "the plan segments and the refresh disclosure must both survive \
                     a 120-column projection: {text}"
                );
                assert!(
                    text.contains(START_MAP_CALL_TO_ACTION),
                    "the call to action must stay on one unbroken line: {text}"
                );
            }
        }
    }

    #[test]
    fn setup_summary_discloses_the_expected_post_map_recommendation_run() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.open_setup();
        let model = setup_readiness_model(&app);
        assert!(model.runnable_tasks > 0, "{model:?}");

        for width in [60u16, 120] {
            let rendered = setup_summary_lines(&model, width as usize)
                .into_iter()
                .map(|line| line.to_string())
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                rendered.contains("+1 expected background recommendation run"),
                "width {width}: {rendered}"
            );
        }
    }

    /// A hydrated engagement whose current latest run already holds a readable
    /// `recommendations.json` still commits the refresh: its Map tasks move the
    /// latest-run pointer to runs without that artifact, and the post-Map check
    /// reads the new pointer. Setup must disclose the run it is committing to.
    #[test]
    fn a_fresh_recommendations_artifact_does_not_hide_the_post_map_refresh() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.open_setup();
        write_latest_run_with_recommendations(target.path(), "run-cached-rec");
        app.invalidate_view_hydration();
        app.hydrate_all_view_data_for_test();
        assert!(
            !crate::ui_view_models::recommendation_artifact_needs_refresh(&app),
            "fixture must present a readable recommendations.json on the latest run"
        );
        let model = setup_readiness_model(&app);
        assert!(model.runnable_tasks > 0, "{model:?}");

        let rendered = setup_summary_lines(&model, 120)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            rendered.contains("+1 expected background recommendation run"),
            "{rendered}"
        );
    }

    /// The mirror case: every checked row is cached and reused, so the plan is
    /// empty, Map never runs, and the refresh must not be promised — even
    /// though no `recommendations.json` exists yet.
    #[test]
    fn an_all_reused_plan_does_not_promise_the_post_map_refresh() {
        let (target, mut app) = reusable_map_app();
        assert!(
            crate::ui_view_models::recommendation_artifact_needs_refresh(&app),
            "fixture must have no recommendations artifact"
        );
        let checked = check_every_cached_row(&mut app);
        assert!(checked > 0, "fixture must offer cached Map rows");
        let model = setup_readiness_model(&app);
        assert_eq!(model.selected_tasks, checked, "{model:?}");
        assert_eq!(model.runnable_tasks, 0, "{model:?}");

        let rendered = setup_summary_lines(&model, 120)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            !rendered.contains("+1 expected background recommendation run"),
            "a reused-only plan never completes Map: {rendered}"
        );
        drop(target);
    }

    fn write_latest_run_with_recommendations(target: &std::path::Path, run_id: &str) {
        let run_dir = kuzushi_core::run_dir(target, run_id);
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::write(
            run_dir.join("recommendations.json"),
            serde_json::json!({"recommendations": []}).to_string(),
        )
        .unwrap();
        let summary =
            kuzushi_core::RunSummary::running(run_id, "tool", None, target.display().to_string());
        kuzushi_core::write_run_summary(target, &summary).unwrap();
    }

    /// Check every row whose artifact is already on disk. Cached rows carry no
    /// rebuild mark, so the picker reports them as reused and the committed
    /// plan drops them — the same transition `cycle_planning_row` performs.
    fn check_every_cached_row(app: &mut ShellApp) -> usize {
        let cached = app
            .engagement
            .planning_picker()
            .tasks()
            .iter()
            .filter(|row| row.artifact_state == crate::app::PlanningArtifactState::Cached)
            .map(|row| row.id)
            .collect::<Vec<_>>();
        let picker = app.engagement.planning_picker_mut();
        for task in &cached {
            picker.selected_mut().insert(*task);
        }
        cached.len()
    }

    #[test]
    fn the_ready_summary_wraps_instead_of_ellipsizing_its_execution_segments() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.open_setup();
        let model = setup_readiness_model(&app);

        let lines = setup_summary_lines(&model, 60);
        let rendered = lines
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let unwrapped = lines
            .iter()
            .map(|line| line.to_string().trim().to_string())
            .collect::<Vec<_>>()
            .join(" ");

        assert!(!rendered.contains('…'), "{rendered}");
        assert!(
            unwrapped.contains(&setup_execution_summary(&model)),
            "{rendered}"
        );
        assert!(unwrapped.contains(START_MAP_CALL_TO_ACTION), "{rendered}");
        for line in &lines {
            assert!(line.to_string().chars().count() <= 60, "{rendered}");
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

    /// A target whose recommended Map artifacts were all produced by a prior
    /// run, so every offered row rests as cached.
    fn reusable_map_app() -> (tempfile::TempDir, ShellApp) {
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
        (target, app)
    }

    #[test]
    fn a_reusable_map_plan_is_not_announced_as_blocked() {
        let (_target, app) = reusable_map_app();

        let text = setup_lines(&app, Rect::new(0, 0, 120, 36))
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("NOTHING TO RUN"), "{text}");
        assert!(text.contains("cached Map artifacts reused"), "{text}");
        assert!(!text.contains("BLOCKED"), "{text}");
        assert!(!text.contains("0 Map task(s)"), "{text}");
        assert!(
            !text.contains("+1 expected background recommendation run"),
            "an empty plan records an explicit Map skip and cannot launch the post-Map refresh: {text}"
        );
    }

    #[test]
    fn setup_renders_generation_checked_active_target_facts() {
        let (_target, app) = setup_app_with_resolved_target_facts();

        let text = setup_text(&app, 120);

        assert!(text.contains("languages: Rust"), "{text}");
        assert!(text.contains("build: Bazel, Cargo"), "{text}");
        assert!(text.contains("prior Kuzushi:"), "{text}");
    }

    #[test]
    fn selected_target_states_its_path_once_ahead_of_its_facts() {
        let (target, mut app) = setup_app_with_resolved_target_facts();
        let target_index = crate::app::SetupRowId::ALL
            .iter()
            .position(|row| *row == crate::app::SetupRowId::Target)
            .unwrap();
        app.router.setup_mut().set_cursor(target_index);
        let path = target.path().display().to_string();

        for width in [120, 160] {
            let text = setup_text(&app, width);
            assert_eq!(text.matches(path.as_str()).count(), 1, "{width}: {text}");
            let path_at = text.find(path.as_str()).unwrap();
            assert!(
                path_at < text.find("languages:").unwrap(),
                "{width}: {text}"
            );
        }
    }

    fn setup_text(app: &ShellApp, width: u16) -> String {
        setup_lines(app, Rect::new(0, 0, width, 36))
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn setup_app_with_resolved_target_facts() -> (tempfile::TempDir, ShellApp) {
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
        (target, app)
    }
}
