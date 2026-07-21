use super::*;
/// How the primary body region is painted this frame. Most views are
/// line-based; Activity, the Workbench command center, and the 3D
/// attack-surface page each own the whole region with a frame-level layout
/// (split panes / half-block framebuffer).
#[derive(Clone, Copy, PartialEq, Eq)]
enum PrimaryRenderMode {
    Lines,
    Activity,
    Scene,
    Workbench,
}

struct PrimaryLayer {
    view: ShellView,
    mode: PrimaryRenderMode,
    height: u16,
    lines: Vec<Line<'static>>,
    has_overlay: bool,
}

fn primary_render_mode(app: &ShellApp, view: ShellView) -> PrimaryRenderMode {
    if view == app.shell_view() {
        return current_primary_render_mode(app);
    }
    match view {
        ShellView::Scene if app.router.scene().page().is_frame_rendered() => {
            PrimaryRenderMode::Scene
        }
        ShellView::Activity => PrimaryRenderMode::Activity,
        ShellView::Workbench => PrimaryRenderMode::Workbench,
        _ => PrimaryRenderMode::Lines,
    }
}

fn current_primary_render_mode(app: &ShellApp) -> PrimaryRenderMode {
    if crate::ui_view_models::uses_scene_frame(app) {
        return PrimaryRenderMode::Scene;
    }
    if crate::ui_view_models::uses_activity_frame(app) {
        return PrimaryRenderMode::Activity;
    }
    if crate::ui_view_models::uses_workbench_frame(app) {
        return PrimaryRenderMode::Workbench;
    }
    PrimaryRenderMode::Lines
}

pub fn render_app(frame: &mut Frame<'_>, app: &ShellApp) {
    let area = frame.area();
    if area.height == 0 || area.width == 0 {
        return;
    }

    let prompt_height = prompt_height(app, area);
    let sections = fit_sections_to_height(render_sections(app, area), area.height, prompt_height);
    let fixed_height = fixed_chrome_height(&sections, prompt_height);
    let max_view_height = area.height.saturating_sub(fixed_height).max(1);
    let primary = primary_layer(app, area, max_view_height);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(render_constraints(primary.height, &sections, prompt_height))
        .split(area);
    render_primary_layer(frame, chunks[0], app, primary);
    render_lower_chrome(frame, app, &chunks, sections);
}

pub(crate) fn workbench_primary_area(app: &ShellApp, area: Rect) -> Rect {
    let prompt_height = prompt_height(app, area);
    let sections = fit_sections_to_height(render_sections(app, area), area.height, prompt_height);
    Rect {
        height: area
            .height
            .saturating_sub(fixed_chrome_height(&sections, prompt_height))
            .max(1),
        ..area
    }
}

fn render_primary_layer(frame: &mut Frame<'_>, area: Rect, app: &ShellApp, primary: PrimaryLayer) {
    render_primary_view(frame, area, app, primary.view, primary.mode, primary.lines);
    if primary.has_overlay {
        render_contextual_overlay(frame, area, app);
    }
}

fn primary_layer(app: &ShellApp, area: Rect, max_height: u16) -> PrimaryLayer {
    let overlay = contextual_overlay_origin(app);
    let view = overlay.unwrap_or_else(|| app.shell_view());
    let mode = primary_render_mode(app, view);
    let force_full_height = mode != PrimaryRenderMode::Lines || overlay.is_some();
    let view_area = Rect {
        height: max_height,
        ..area
    };
    let (height, lines) =
        main_view_layout(app, view, mode, force_full_height, max_height, view_area);
    PrimaryLayer {
        view,
        mode,
        height,
        lines,
        has_overlay: overlay.is_some(),
    }
}

fn render_lower_chrome(
    frame: &mut Frame<'_>,
    app: &ShellApp,
    chunks: &[Rect],
    sections: Vec<RenderSectionSlot>,
) {
    let mut index = 2;
    for section in sections {
        section.kind.render(frame, chunks[index], app);
        index += 1;
    }
    render_input_surface(frame, chunks[index], app);
}

fn render_input_surface(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if let Some(question) = app.guided_scan_question_model() {
        let page = crate::ui_view_models::active_workbench_page(app);
        crate::renderer::render_guided_question(frame, area, page, &question);
        return;
    }
    if render_operator_question_input(frame, area, app) {
        return;
    }
    render_prompt(frame, area, app);
}

fn main_view_layout(
    app: &ShellApp,
    view: ShellView,
    mode: PrimaryRenderMode,
    force_full_height: bool,
    max_view_height: u16,
    view_area: Rect,
) -> (u16, Vec<Line<'static>>) {
    if mode != PrimaryRenderMode::Lines {
        return (max_view_height, Vec::new());
    }

    let view_lines = shell_view_lines_for(app, view_area, view);
    let view_height = if force_full_height {
        max_view_height
    } else {
        line_view_height(view, view_lines.len(), max_view_height)
    };
    (view_height, view_lines)
}

fn line_view_height(view: ShellView, line_count: usize, max_view_height: u16) -> u16 {
    if matches!(
        view,
        crate::ShellView::PlanningPicker | crate::ShellView::Setup
    ) {
        return max_view_height;
    }
    (line_count as u16).clamp(1, max_view_height)
}

fn render_primary_view(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    view: ShellView,
    mode: PrimaryRenderMode,
    view_lines: Vec<Line<'static>>,
) {
    match mode {
        PrimaryRenderMode::Scene => render_scene_view(frame, area, app),
        PrimaryRenderMode::Activity => render_activity_view(frame, area, app),
        PrimaryRenderMode::Workbench => render_workbench_view(frame, area, app),
        PrimaryRenderMode::Lines => render_line_view(frame, area, view, view_lines),
    }
}

fn render_line_view(
    frame: &mut Frame<'_>,
    area: Rect,
    _view: ShellView,
    view_lines: Vec<Line<'static>>,
) {
    render_lines(frame, area, view_lines);
}

fn contextual_overlay_origin(app: &ShellApp) -> Option<ShellView> {
    if !matches!(
        app.shell_view(),
        ShellView::Catalog
            | ShellView::CommandPalette
            | ShellView::ConfirmDialog
            | ShellView::QuitConfirm
            | ShellView::ThemePicker
            | ShellView::Keymap
            | ShellView::UpdateAvailable
            | ShellView::Help
    ) {
        return None;
    }
    app.router
        .overlay_origin()
        .filter(|view| *view != app.shell_view())
}

fn render_contextual_overlay(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if app.shell_view() == ShellView::CommandPalette {
        render_command_palette_overlay(frame, area, app);
        return;
    }
    render_system_overlay(frame, area, app);
}

pub(crate) const PROMPT_HEIGHT: u16 = 1;

fn prompt_height(app: &ShellApp, area: Rect) -> u16 {
    if let Some(question) = app.guided_scan_question_model() {
        return crate::renderer::guided_question_height(area, &question);
    }
    if let Some(height) = operator_question_input_height(app, area) {
        return height;
    }
    if activity_navigation_owns_input_surface(app) {
        0
    } else {
        PROMPT_HEIGHT
    }
}

fn activity_navigation_owns_input_surface(app: &ShellApp) -> bool {
    matches!(
        (app.shell_view(), app.input_mode()),
        (ShellView::Activity, crate::InputMode::Navigate)
    )
}

#[cfg(test)]
mod run_focus_prompt_tests {
    use super::*;
    use crate::app::{
        OperatorQuestion, OperatorQuestionEnvelope, OperatorQuestionOption,
        OperatorQuestionRequest, PendingOperatorQuestion, WorkerGeneration,
    };
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::sync::mpsc::sync_channel;

    fn app_with_operator_question() -> ShellApp {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        let (control, _receiver) = sync_channel(8);
        let mut session = crate::ActivitySession::new("run-question");
        session.operator_question = Some(PendingOperatorQuestion::new(OperatorQuestionEnvelope {
            request: OperatorQuestionRequest {
                request_id: "question-1".to_string(),
                run_id: "run-question".to_string(),
                questions: vec![OperatorQuestion {
                    id: "scope".to_string(),
                    header: "Scope".to_string(),
                    prompt: "What should Scan inspect?".to_string(),
                    options: vec![
                        OperatorQuestionOption {
                            label: "Changed files".to_string(),
                            description: "Fast focused scan".to_string(),
                            recommended: true,
                        },
                        OperatorQuestionOption {
                            label: "Repository".to_string(),
                            description: "Broad scan".to_string(),
                            recommended: false,
                        },
                    ],
                }],
                auto_resolution_ms: None,
            },
            generation: WorkerGeneration::new(1),
            control,
        }));
        app.set_activity(Some(session));
        app.set_shell_view(ShellView::Activity);
        app
    }

    fn buffer_rows(buffer: &ratatui::buffer::Buffer) -> Vec<String> {
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect()
    }

    fn render_activity_prompt_rows(width: u16, height: u16, draft: &str) -> Vec<String> {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_activity(Some(crate::ActivitySession::new("run-prompt")));
        app.set_shell_view(ShellView::Activity);
        app.set_input_mode(crate::InputMode::Prompt);
        app.set_input(draft);
        assert!(matches!(
            crate::ui_view_models::activity_view_model(&app),
            crate::ui_view_models::ActivityViewModel::Active(_)
        ));
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|frame| render_app(frame, &app)).unwrap();

        buffer_rows(terminal.backend().buffer())
    }

    #[test]
    fn run_focus_navigation_owns_input_while_prompt_reserves_composer_row() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_shell_view(ShellView::Activity);
        app.set_input_mode(crate::InputMode::Navigate);
        assert_eq!(prompt_height(&app, Rect::new(0, 0, 80, 24)), 0);

        app.set_input_mode(crate::InputMode::Prompt);
        assert_eq!(prompt_height(&app, Rect::new(0, 0, 80, 24)), PROMPT_HEIGHT);

        app.set_shell_view(ShellView::Workbench);
        assert_eq!(prompt_height(&app, Rect::new(0, 0, 80, 24)), PROMPT_HEIGHT);
    }

    #[test]
    fn activity_prompt_draft_is_visible_at_compact_and_wide_sizes() {
        for (width, height) in [(40, 12), (120, 36)] {
            let rows = render_activity_prompt_rows(width, height, "xyzz");
            let prompt = rows.last().expect("reserved Activity prompt row");

            assert!(prompt.contains("xyzz"), "{width}x{height}: {rows:?}");
        }
    }

    #[test]
    fn operator_question_renders_beside_bottom_input_locus_at_40x12() {
        let app = app_with_operator_question();
        assert!(prompt_height(&app, Rect::new(0, 0, 40, 12)) > PROMPT_HEIGHT);
        let backend = TestBackend::new(40, 12);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|frame| render_app(frame, &app)).unwrap();

        let rows = buffer_rows(terminal.backend().buffer());
        let waiting_row = rows
            .iter()
            .rposition(|row| row.contains("WAITING INPUT"))
            .expect("question title");
        let question = rows[waiting_row..].join("\n");
        assert!(
            waiting_row >= 6,
            "question must occupy bottom rows: {rows:?}"
        );
        assert!(question.contains("What should Scan inspect?"), "{question}");
        assert!(question.contains("Changed files"), "{question}");
        assert!(question.contains("Enter submit"), "{question}");
    }

    #[test]
    fn background_question_preserves_the_workbench_composer_draft() {
        let mut app = app_with_operator_question();
        app.activity_mut().unwrap().run_focus_backgrounded = true;
        app.engagement.set_phase(kuzushi_core::WorkflowPhase::Map);
        app.set_shell_view(ShellView::Workbench);
        app.router
            .workbench_mut()
            .set_page(Some(crate::WorkbenchPage::Map));
        app.set_input_mode(crate::InputMode::Prompt);
        app.set_input("jobs");
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|frame| render_app(frame, &app)).unwrap();

        let rows = buffer_rows(terminal.backend().buffer());
        let prompt = rows.last().expect("prompt row");
        assert!(prompt.contains("MAP"), "{rows:?}");
        assert!(prompt.contains("jobs"), "{rows:?}");
        assert!(!prompt.contains("WAITING INPUT"), "{rows:?}");
        assert!(
            rows.iter().any(|row| row.contains("1 question waiting")),
            "background attention must remain visible: {rows:?}"
        );
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RenderSectionSlot {
    pub(crate) kind: RenderSection,
    pub(crate) height: u16,
}

#[derive(Clone, Copy)]
#[repr(usize)]
pub(crate) enum RenderSection {
    Notice,
    Throttle,
    Status,
    Keybind,
    Budget,
    Plan,
    ThreatPatch,
    Confirm,
    Retry,
    PrereqPrompt,
    Transcript,
    /// Completion popup (M3 §3.3). Sits just above the prompt when a
    /// completion cycle is active, showing up to 6 candidates with the
    /// selected one highlighted.
    CompletionPopup,
}

impl RenderSection {
    pub(crate) fn render(self, frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
        RENDER_SECTION_HANDLERS[self as usize](frame, area, app);
    }
}

type RenderSectionHandler = fn(&mut Frame<'_>, Rect, &ShellApp);

const RENDER_SECTION_HANDLERS: &[RenderSectionHandler] = &[
    render_notice_banner,
    render_throttle_banner,
    render_status_footer,
    render_keybind_footer,
    render_cost_cap_halt,
    render_plan_card,
    render_threat_patch_card,
    render_confirm_card,
    render_retry_card,
    render_prereq_prompt_card,
    render_transcript,
    render_completion_popup,
];

pub(crate) fn render_sections(app: &ShellApp, area: Rect) -> Vec<RenderSectionSlot> {
    // `fit_sections_to_height` sheds from the tail. Keep every surface that
    // owns an operator decision ahead of observational chrome: a key must
    // never be captured by a confirmation/prerequisite that is no longer on
    // screen in a 40x12 terminal.
    [
        section_slot(RenderSection::Budget, cost_cap_halt_height(app, area)),
        section_slot(
            RenderSection::ThreatPatch,
            threat_patch_card_height(app, area),
        ),
        section_slot(RenderSection::Confirm, confirm_card_height(app, area)),
        section_slot(
            RenderSection::PrereqPrompt,
            prereq_prompt_card_height(app, area),
        ),
        section_slot(RenderSection::Retry, retry_card_height(app, area)),
        section_slot(RenderSection::Plan, plan_card_height(app, area)),
        section_slot(RenderSection::Status, status_footer_height(app, area)),
        section_slot(RenderSection::Keybind, keybind_footer_height(app, area)),
        section_slot(RenderSection::Notice, notice_banner_height(app, area)),
        section_slot(RenderSection::Throttle, throttle_banner_height(app, area)),
        section_slot(RenderSection::Transcript, transcript_height(app, area)),
        section_slot(
            RenderSection::CompletionPopup,
            completion_popup_height(app, area),
        ),
    ]
    .into_iter()
    .flatten()
    .collect()
}
