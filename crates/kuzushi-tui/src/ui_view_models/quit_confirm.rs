use super::{cost_model, format_session_cost};
use crate::{
    QuitConfirmFooter, QuitConfirmSection, QuitConfirmSnapshot, QuitConfirmStatus, ShellApp,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuitConfirmModel {
    pub(crate) status: QuitConfirmStatus,
    pub(crate) timestamp: String,
    pub(crate) warning_title: String,
    pub(crate) warning_body: String,
    pub(crate) sections: Vec<QuitConfirmSection>,
    pub(crate) default_line: String,
    pub(crate) footer: QuitConfirmFooter,
}

pub(crate) fn quit_confirm_model(app: &ShellApp) -> QuitConfirmModel {
    app.quit_confirm_snapshot()
        .cloned()
        .map(QuitConfirmModel::from)
        .unwrap_or_else(|| default_quit_confirm_model(app))
}

impl From<QuitConfirmSnapshot> for QuitConfirmModel {
    fn from(snapshot: QuitConfirmSnapshot) -> Self {
        Self {
            status: snapshot.status,
            timestamp: snapshot.timestamp,
            warning_title: snapshot.warning_title,
            warning_body: snapshot.warning_body,
            sections: snapshot.sections,
            default_line: snapshot.default_line,
            footer: snapshot.footer,
        }
    }
}

fn default_quit_confirm_model(app: &ShellApp) -> QuitConfirmModel {
    let active_count = usize::from(app.has_running_work());
    let volatile_rows = volatile_session_rows(app);
    QuitConfirmModel {
        status: default_status(app),
        timestamp: "--:--:--".to_string(),
        warning_title: "CONFIRM SESSION EXIT".to_string(),
        warning_body: default_warning(active_count, !volatile_rows.is_empty()),
        sections: context_draft_sections(app, default_sections(active_count, volatile_rows)),
        default_line: "default · n/N/Esc · stay".to_string(),
        footer: default_footer(app, active_count),
    }
}

fn default_warning(active_count: usize, has_volatile_state: bool) -> String {
    if active_count > 0 {
        "the shell will request active-work cancellation and cleanup before exiting".to_string()
    } else if has_volatile_state {
        "no active work is running; the not-saved session state below will be discarded".to_string()
    } else {
        "no active work is running; exiting will close the shell".to_string()
    }
}

fn default_status(app: &ShellApp) -> QuitConfirmStatus {
    QuitConfirmStatus {
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
        module: "quit".to_string(),
        cost: default_cost(app),
    }
}

fn default_cost(app: &ShellApp) -> String {
    cost_model(app)
        .budget_status
        .map(|status| status.cells[1].clone())
        .unwrap_or_else(|| format_session_cost(0.0))
}

fn default_sections(active_count: usize, volatile_rows: Vec<String>) -> Vec<QuitConfirmSection> {
    let mut sections = vec![QuitConfirmSection::new(
        default_in_flight_title(active_count),
        default_in_flight_rows(active_count),
    )];
    if !volatile_rows.is_empty() {
        sections.push(QuitConfirmSection::new("NOT SAVED", volatile_rows));
    }
    sections.push(QuitConfirmSection::new(
        "CHOOSE",
        default_choice_rows(active_count),
    ));
    sections
}

pub(crate) fn has_volatile_session_state(app: &ShellApp) -> bool {
    !volatile_session_rows(app).is_empty()
}

fn volatile_session_rows(app: &ShellApp) -> Vec<String> {
    [
        queued_commands_row(app),
        session_budget_row(app),
        budget_draft_row(app),
        planning_option_draft_row(app),
        tool_option_draft_row(app),
        report_path_draft_row(app),
        map_text_draft_row(app),
        batch_number_draft_row(app),
        context_cases_draft_row(app),
        model_study_draft_row(app),
        scope_draft_row(app),
        goal_draft_row(app),
        context_copy_draft_row(app),
        context_checkpoint_pending_row(app),
        context_checkpoint_cleanup_row(app),
        study_checkpoint_pending_row(app),
        study_checkpoint_cleanup_row(app),
        answer_draft_row(app),
        setup_plan_row(app),
        prompt_draft_row(app),
        credential_draft_row(app),
        command_draft_row(app),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn scope_draft_row(app: &ShellApp) -> Option<String> {
    let state = app.router.scope_review().as_ref()?;
    (state.form.is_some() || state.new_scope_draft.is_some()).then(|| {
        "    !   scope draft   session-only edits will be discarded; content hidden".into()
    })
}

fn tool_option_draft_row(app: &ShellApp) -> Option<String> {
    let state = app.router.options_browser();
    (state.edit.is_some() || !state.drafts.is_empty()).then(|| {
        "    !   tool option drafts   unsaved values will be discarded; content hidden".to_string()
    })
}

fn answer_draft_row(app: &ShellApp) -> Option<String> {
    app.router.answers().has_drafts().then(|| {
        "    !   Ask drafts   unsent questions will be discarded; content hidden".to_string()
    })
}

fn report_path_draft_row(app: &ShellApp) -> Option<String> {
    app.router.report().editing_path().then(|| {
        "    !   report destination draft   active edit will be discarded; content hidden"
            .to_string()
    })
}

fn queued_commands_row(app: &ShellApp) -> Option<String> {
    let queued = app.steer_queue().len();
    (queued > 0).then(|| format!("    !   queued commands   {queued} will be discarded"))
}

fn session_budget_row(app: &ShellApp) -> Option<String> {
    (app.session().session_budget_usd() != app.config().operator.session_budget_usd)
        .then(|| "    !   session budget   changed for this session only".to_string())
}

fn budget_draft_row(app: &ShellApp) -> Option<String> {
    (app.router.setup().editor() == Some(crate::app::SetupEditor::Budget))
        .then(|| "    !   budget draft   active edit will be discarded; content hidden".to_string())
}

fn planning_option_draft_row(app: &ShellApp) -> Option<String> {
    app.engagement
        .planning_picker()
        .option_edit()
        .is_some()
        .then(|| {
            "    !   planning option draft   active edit will be discarded; content hidden"
                .to_string()
        })
}

fn setup_plan_row(app: &ShellApp) -> Option<String> {
    let picker = app.engagement.planning_picker();
    (!picker.selected().is_empty())
        .then(|| "    !   planning selection   session choices will be discarded".to_string())
}

fn map_text_draft_row(app: &ShellApp) -> Option<String> {
    app.router.setup().map_run_config().has_unsaved_text().then(|| {
        "    !   Map draft   unsaved document or context edits will be discarded; content hidden".to_string()
    })
}

fn batch_number_draft_row(app: &ShellApp) -> Option<String> {
    if app.study_choices_checkpointed() {
        return None;
    }
    app.router
        .campaign()
        .batch_scan_config
        .as_ref()?
        .number_edit
        .as_ref()
        .filter(|edit| !edit.field.text().is_empty())
        .map(|_| "    !   batch number draft   unsaved value will be discarded".to_string())
}

fn context_cases_draft_row(app: &ShellApp) -> Option<String> {
    app.study_choices_not_checkpointed()
        .then(|| "    !   study choices   uncheckpointed settings or goal edits will be discarded; content hidden".into())
}

fn goal_draft_row(app: &ShellApp) -> Option<String> {
    app.uncheckpointed_goal_drafts().then(|| {
        "    !   goal draft   uncheckpointed text will be discarded; content hidden".into()
    })
}

fn model_study_draft_row(app: &ShellApp) -> Option<String> {
    app.has_session_only_model_study_choices().then(|| {
        "    !   model study draft   session-only inputs or limits will be discarded; content hidden".into()
    })
}

fn study_checkpoint_pending_row(app: &ShellApp) -> Option<String> {
    app.study_checkpoint_pending().then(|| "    !   study draft write   latest choices are not yet durable; stay for the save result".into())
}

fn study_checkpoint_cleanup_row(app: &ShellApp) -> Option<String> {
    app.study_checkpoint_cleanup_failed().then(|| "    !   study draft cleanup   failed; an older draft may recover; inspect saved plans before preparing another".into())
}

fn context_copy_draft_row(app: &ShellApp) -> Option<String> {
    app.context_copies_not_checkpointed().then(|| {
        "    !   context copy   unsaved edits will be discarded; return to review and save; content hidden".into()
    })
}

fn context_checkpoint_pending_row(app: &ShellApp) -> Option<String> {
    app.context_checkpoints_pending().then(|| "    !   local draft write   latest edits or discard are not yet durable; stay for the save result".into())
}

fn context_checkpoint_cleanup_row(app: &ShellApp) -> Option<String> {
    app.context_checkpoint_cleanup_failed().then(|| "    !   local draft cleanup   failed; an older checkpoint may recover; inspect the context catalog before saving another copy".into())
}

fn context_draft_sections(
    app: &ShellApp,
    mut sections: Vec<QuitConfirmSection>,
) -> Vec<QuitConfirmSection> {
    let rows = recoverable_draft_rows(app);
    if !rows.is_empty() {
        let index = sections.len().saturating_sub(1);
        sections.insert(index, QuitConfirmSection::new("RECOVERABLE DRAFTS", rows));
    }
    sections
}

fn recoverable_draft_rows(app: &ShellApp) -> Vec<String> {
    [
        app.study_choices_checkpointed().then(|| "study choices · local checkpoint saved; reopen scan batch to recover; work needs approval".into()),
        app.context_copies_checkpointed().then(|| "context copy · local checkpoint saved; inspect the same context to recover it".into()),
    ].into_iter().flatten().collect()
}

fn prompt_draft_row(app: &ShellApp) -> Option<String> {
    app.router
        .prompts()
        .document()
        .is_some_and(|document| document.dirty)
        .then(|| {
            "    !   prompt draft   unsaved edits will be discarded; content hidden".to_string()
        })
}

fn credential_draft_row(app: &ShellApp) -> Option<String> {
    (!app.router.auth_picker().key_draft().is_empty()).then(|| {
        "    !   credential draft   unsaved input will be discarded; content hidden".to_string()
    })
}

fn command_draft_row(app: &ShellApp) -> Option<String> {
    let draft_chars = app.input().chars().count();
    (draft_chars > 0).then(|| {
        format!(
            "    !   command draft   {draft_chars} characters will be discarded; content hidden"
        )
    })
}

fn default_in_flight_title(active_count: usize) -> &'static str {
    if active_count > 0 {
        "IN FLIGHT · cancellation requested before exit"
    } else {
        "IN FLIGHT"
    }
}

fn default_choice_rows(active_count: usize) -> Vec<String> {
    let exit_detail = if active_count > 0 {
        "cancel active work if needed, then exit"
    } else {
        "close the shell"
    };
    vec![
        format!("    y/Y       exit   {exit_detail}"),
        "    n/N/Esc   stay   keep this session open".to_string(),
    ]
}

fn default_in_flight_rows(active_count: usize) -> Vec<String> {
    if active_count > 0 {
        vec!["    ⏵   active work   running · cancellation requested on exit".to_string()]
    } else {
        vec!["    ·   no active work".to_string()]
    }
}

fn default_footer(app: &ShellApp, active_count: usize) -> QuitConfirmFooter {
    let (stage, exit_label) = if active_count > 0 {
        ("quit · active work running", "cancel if needed + exit")
    } else {
        ("quit · no active work", "exit")
    };
    QuitConfirmFooter {
        stage: stage.to_string(),
        findings: app.findings_total_count(),
        keybinds: vec![
            ("y/Y".to_string(), exit_label.to_string()),
            ("n/N/Esc".to_string(), "stay".to_string()),
        ],
        prompt_module: "quit".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::QueuedCommand;
    use kuzushi_core::V2Config;

    #[test]
    fn quit_confirm_model_uses_route_owned_snapshot() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.replace_quit_confirm_snapshot_for_test(Some(QuitConfirmSnapshot {
            status: QuitConfirmStatus {
                target: "target".to_string(),
                ctx: "ctx".to_string(),
                model: "model".to_string(),
                module: "quit".to_string(),
                cost: "$0.00".to_string(),
            },
            timestamp: "12:00:00".to_string(),
            warning_title: "ROUTE SNAPSHOT".to_string(),
            warning_body: "body".to_string(),
            sections: vec![QuitConfirmSection::new("SECTION", vec!["row".to_string()])],
            default_line: "default".to_string(),
            footer: QuitConfirmFooter {
                stage: "quit".to_string(),
                findings: 0,
                keybinds: Vec::new(),
                prompt_module: "quit".to_string(),
            },
        }));

        let model = quit_confirm_model(&app);

        assert_eq!(model.warning_title, "ROUTE SNAPSHOT");
        assert_eq!(model.sections.len(), 1);
        assert_eq!(model.footer.prompt_module, "quit");
    }

    #[test]
    fn idle_quit_confirm_only_offers_exit_or_stay() {
        let app = ShellApp::new(V2Config::default(), None);

        let model = quit_confirm_model(&app);

        assert_eq!(
            model.warning_body,
            "no active work is running; exiting will close the shell"
        );
        assert_eq!(model.sections[0].title, "IN FLIGHT");
        assert_eq!(model.sections[1].rows, default_choice_rows(0));
        assert_eq!(
            model.footer.keybinds,
            vec![
                ("y/Y".to_string(), "exit".to_string()),
                ("n/N/Esc".to_string(), "stay".to_string()),
            ]
        );
        assert_no_unimplemented_quit_claims(&model);
    }

    #[test]
    fn active_quit_confirm_explains_cancel_then_exit() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_running_tool_for_test("semgrep:scan");

        let model = quit_confirm_model(&app);

        assert!(model
            .warning_body
            .contains("request active-work cancellation and cleanup"));
        assert_eq!(
            model.sections[0].title,
            "IN FLIGHT · cancellation requested before exit"
        );
        assert!(model.sections[1].rows[0].contains("cancel active work if needed, then exit"));
        assert_eq!(
            model.footer.keybinds,
            vec![
                ("y/Y".to_string(), "cancel if needed + exit".to_string()),
                ("n/N/Esc".to_string(), "stay".to_string()),
            ]
        );
        assert_no_unimplemented_quit_claims(&model);
    }

    #[test]
    fn quit_confirm_discloses_volatile_state_without_echoing_draft_content() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.steer_queue_mut().enqueue(QueuedCommand {
            raw: "run semgrep:scan".to_string(),
            summary: "semgrep".to_string(),
        });
        app.session_mut().set_session_budget_usd(Some(2.0));
        app.set_input("secret draft");

        let model = quit_confirm_model(&app);
        let volatile = model
            .sections
            .iter()
            .find(|section| section.title == "NOT SAVED")
            .expect("not-saved section");
        let text = volatile.rows.join("\n");

        assert!(text.contains("1 will be discarded"));
        assert!(text.contains("session budget"));
        assert!(text.contains("12 characters"));
        assert!(!text.contains("secret draft"));
    }

    #[test]
    fn quit_confirm_discloses_active_setup_drafts_without_echoing_content() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.router.setup_mut().begin_budget_edit(None);
        app.router.setup_mut().insert_budget_text("9");
        app.engagement.planning_picker_mut().set_option_edit(Some(
            crate::app::PlanningOptionEdit::new(
                crate::app::PlanningTaskId::GatherRepoContext,
                "scope",
                "secret scope",
            ),
        ));

        let model = quit_confirm_model(&app);
        let text = model
            .sections
            .iter()
            .find(|section| section.title == "NOT SAVED")
            .expect("not-saved section")
            .rows
            .join("\n");

        assert!(text.contains("budget draft"));
        assert!(text.contains("planning option draft"));
        assert!(!text.contains("secret scope"));
    }

    #[test]
    fn quit_confirm_discloses_phase_planner_selection() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.engagement
            .planning_picker_mut()
            .selected_mut()
            .insert(crate::app::PlanningTaskId::ScanSemgrep);
        app.engagement
            .planning_picker_mut()
            .set_return_to_setup(false);

        let model = quit_confirm_model(&app);
        let text = model
            .sections
            .iter()
            .find(|section| section.title == "NOT SAVED")
            .expect("not-saved section")
            .rows
            .join("\n");

        assert!(text.contains("planning selection"));
        assert!(text.contains("session choices will be discarded"));
    }

    fn assert_no_unimplemented_quit_claims(model: &QuitConfirmModel) {
        let visible_copy = format!(
            "{} {:?} {:?}",
            model.warning_body, model.sections, model.footer.keybinds
        );
        for unsupported in ["checkpoint", "story", "detach", "resumable"] {
            assert!(
                !visible_copy.to_ascii_lowercase().contains(unsupported),
                "quit confirmation must not advertise unsupported `{unsupported}` behavior"
            );
        }
    }
}
