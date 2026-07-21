use super::*;
use crate::scene3d::VizPage;
use std::path::{Component, Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FocusedWorkbenchVisualization {
    Scene(VizPage),
    ProofReplay,
}

impl ShellApp {
    pub(super) fn handle_view_hotkey(&mut self, key: KeyEvent) -> InputUpdate {
        let Some(binding) = self
            .view_keybindings()
            .into_iter()
            .find(|binding| binding.matches(key))
        else {
            return InputUpdate::handled_if(self.handle_generic_scroll_hotkey(key));
        };
        let char_trigger = binding.trigger.is_char();
        let update = self.apply_view_hotkey(binding.action);
        if update.handled && char_trigger {
            self.ui_mut().record_operator_interaction(Instant::now());
        }
        update
    }

    pub(super) fn apply_view_hotkey(&mut self, action: ViewHotkeyAction) -> InputUpdate {
        if let Some(update) = self.apply_workbench_hotkey(action) {
            return update;
        }
        self.apply_focused_view_hotkey(action)
    }

    /// The `bool`-returning handlers, tried in order; each mutates and reports
    /// whether it claimed the action (short-circuit, like the `if` chain).
    fn apply_focused_view_hotkey(&mut self, action: ViewHotkeyAction) -> InputUpdate {
        for handler in FOCUSED_HOTKEY_HANDLERS {
            let update = handler(self, action);
            if update.handled {
                return update;
            }
        }
        self.apply_shell_hotkey(action)
    }

    /// Pane-aware Workbench navigation: `Tab` cycles focus, `j/k` or arrows
    /// move within the focused pane (FINDINGS cursor, or other pane scroll),
    /// `g/G` jump, and `Enter` selects the cursored finding.
    fn apply_workbench_hotkey(&mut self, action: ViewHotkeyAction) -> Option<InputUpdate> {
        match action {
            ViewHotkeyAction::WorkbenchCyclePane => self.cycle_workbench_pane(false),
            ViewHotkeyAction::WorkbenchCyclePanePrev => self.cycle_workbench_pane(true),
            ViewHotkeyAction::WorkbenchScrollNext => self.workbench_move(1),
            ViewHotkeyAction::WorkbenchScrollPrev => self.workbench_move(-1),
            ViewHotkeyAction::WorkbenchScrollFirst => self.workbench_jump(true),
            ViewHotkeyAction::WorkbenchScrollLast => self.workbench_jump(false),
            ViewHotkeyAction::WorkbenchOpenFocusedVisualization => {
                self.open_workbench_focused_viz()
            }
            ViewHotkeyAction::WorkbenchTogglePaneZoom => self.toggle_workbench_pane_zoom(),
            ViewHotkeyAction::WorkbenchOpen => self.workbench_open_focused(),
            ViewHotkeyAction::WorkbenchPageNext => {
                self.set_workbench_page(crate::ui_view_models::active_workbench_page(self).next())
            }
            ViewHotkeyAction::WorkbenchPagePrev => {
                self.set_workbench_page(crate::ui_view_models::active_workbench_page(self).prev())
            }
            ViewHotkeyAction::WorkbenchPage(page) => self.set_workbench_page(page),
            ViewHotkeyAction::WorkbenchValidate => return Some(self.draft_workbench_validation()),
            ViewHotkeyAction::WorkbenchDeferProof => {
                return Some(self.draft_workbench_proof_deferral())
            }
            ViewHotkeyAction::WorkbenchReverifyPatch => {
                return Some(self.draft_workbench_patch_reverification())
            }
            ViewHotkeyAction::WorkbenchSuppress => return Some(self.draft_workbench_suppression()),
            ViewHotkeyAction::WorkbenchInvariantHunt => {
                return Some(self.draft_workbench_invariant_hunt())
            }
            ViewHotkeyAction::WorkbenchOrderChain => return Some(self.draft_workbench_chain()),
            ViewHotkeyAction::WorkbenchChainFold => return Some(self.draft_workbench_chain_fold()),
            ViewHotkeyAction::WorkbenchCluster => self.open_workbench_coverage_clusters(),
            ViewHotkeyAction::WorkbenchBacklogToggle => self.toggle_review_backlog_preset(),
            ViewHotkeyAction::WorkbenchBacklogDecide(verdict) => {
                return Some(self.apply_backlog_one_key_decision(verdict))
            }
            ViewHotkeyAction::WorkbenchBacklogSeverityCycle => self.cycle_backlog_severity_filter(),
            ViewHotkeyAction::WorkbenchBacklogToolCycle => self.cycle_backlog_tool_filter(),
            ViewHotkeyAction::WorkbenchBacklogBulkDefer => {
                return Some(self.apply_backlog_bulk_defer())
            }
            ViewHotkeyAction::WorkbenchBacklogUndo => return Some(self.apply_backlog_undo()),
            ViewHotkeyAction::Back if self.focus_workbench_findings_before_back() => {}
            _ => return None,
        }
        Some(InputUpdate::handled())
    }

    pub(super) fn set_workbench_page(&mut self, page: WorkbenchPage) {
        let workbench = self.router.workbench_mut();
        workbench.set_page(Some(page));
        workbench.scroll_mut().set(page.primary_surface(), 0);
        workbench.set_focus(page.primary_surface());
        self.set_shell_view(ShellView::Workbench);
    }

    pub(super) fn cycle_workbench_page_mode(&mut self) {
        let page = crate::ui_view_models::active_workbench_page(self).next();
        self.set_workbench_page(page);
    }

    fn cycle_workbench_pane(&mut self, reverse: bool) {
        let Some(plan) = current_phase_plan(self) else {
            return;
        };
        let page = crate::ui_view_models::active_workbench_page(self);
        let stored_focus = self.router.workbench().focus_for(page);
        let current = plan
            .available_surfaces
            .iter()
            .position(|surface| surface.id == stored_focus)
            .unwrap_or_default();
        let next = cycle_index(current, plan.available_surfaces.len(), reverse);
        let next_surface = plan.available_surfaces[next];
        let hidden = plan.surface(next_surface.id).is_none();
        if hidden {
            self.router
                .workbench_mut()
                .show_zoomed_focus(next_surface.id);
        } else {
            self.router.workbench_mut().set_focus(next_surface.id);
        }
    }

    fn open_workbench_focused_viz(&mut self) {
        let Some(surface) = effective_phase_surface(self) else {
            return;
        };
        match focused_workbench_visualization(surface.id) {
            FocusedWorkbenchVisualization::Scene(scene) => self.open_scene_to_page(scene),
            FocusedWorkbenchVisualization::ProofReplay => self.open_confirm_proof_replay(),
        }
    }

    fn open_confirm_proof_replay(&mut self) {
        let model = crate::ui_view_models::phase_cockpit_model_for_phase(
            self,
            kuzushi_core::WorkflowPhase::Prove,
        );
        let crate::ui_view_models::PhaseCockpitBody::Prove(confirm) = model.body else {
            return;
        };
        let Some(run_id) = confirm.proof.and_then(|proof| proof.replay_run_id) else {
            self.log(
                "workbench",
                "proof replay unavailable — run `verify <finding>` to record replayable proof",
            );
            return;
        };
        self.push_nav_history(self.shell_view());
        self.router.replay_mut().open(run_id.clone());
        self.set_shell_view(ShellView::Replay);
        self.log("replay", run_id);
    }

    fn toggle_workbench_pane_zoom(&mut self) {
        let focus = self.normalize_workbench_focus();
        self.router.workbench_mut().toggle_zoom(focus);
    }

    fn normalize_workbench_focus(&mut self) -> crate::ui_view_models::PhaseSurfaceId {
        current_phase_plan(self)
            .map(|plan| plan.effective_focus)
            .unwrap_or_else(|| crate::ui_view_models::active_workbench_page(self).primary_surface())
    }

    fn focus_workbench_findings_before_back(&mut self) -> bool {
        if self.shell_view() != ShellView::Workbench
            || crate::ui_view_models::active_workbench_page(self) != WorkbenchPage::Review
            || effective_phase_surface(self).map(|surface| surface.id)
                != Some(crate::ui_view_models::PhaseSurfaceId::ReviewDetail)
        {
            return false;
        }
        let page = crate::ui_view_models::active_workbench_page(self);
        self.router
            .workbench_mut()
            .set_focus(page.primary_surface());
        self.log(
            "workbench",
            format!(
                "returned to {} — Esc again to leave",
                page.title().to_ascii_lowercase()
            ),
        );
        true
    }

    fn workbench_move(&mut self, delta: isize) {
        let Some(surface) = effective_phase_surface(self) else {
            return;
        };
        match surface.interaction {
            crate::ui_view_models::SurfaceInteraction::Selectable => {
                self.step_findings_cursor(delta)
            }
            crate::ui_view_models::SurfaceInteraction::Scrollable => {
                self.router.workbench_mut().scroll_mut().shift(
                    surface.id,
                    delta.clamp(i32::MIN as isize, i32::MAX as isize) as i32,
                );
            }
            crate::ui_view_models::SurfaceInteraction::Static
            | crate::ui_view_models::SurfaceInteraction::Diagram => {}
        }
    }

    fn step_findings_cursor(&mut self, delta: isize) {
        let len = crate::ui_view_models::visible_findings_len(self);
        self.router.findings_mut().step_direction(delta, len);
        self.reset_workbench_detail_scroll();
    }

    fn workbench_jump(&mut self, to_start: bool) {
        let Some(surface) = effective_phase_surface(self) else {
            return;
        };
        match surface.interaction {
            crate::ui_view_models::SurfaceInteraction::Selectable => {
                let len = crate::ui_view_models::visible_findings_len(self);
                self.router.findings_mut().jump(to_start, len);
                self.reset_workbench_detail_scroll();
            }
            crate::ui_view_models::SurfaceInteraction::Scrollable => {
                self.router
                    .workbench_mut()
                    .scroll_mut()
                    .set(surface.id, if to_start { 0 } else { u16::MAX });
            }
            crate::ui_view_models::SurfaceInteraction::Static
            | crate::ui_view_models::SurfaceInteraction::Diagram => {}
        }
    }

    fn workbench_open_focused(&mut self) {
        use crate::ui_view_models::PhaseSurfaceId;
        let page = crate::ui_view_models::active_workbench_page(self);
        match self.normalize_workbench_focus() {
            PhaseSurfaceId::ReviewQueue if page == WorkbenchPage::Review => {
                let can_open = crate::ui_view_models::visible_finding_at_cursor(self).is_some();
                if can_open {
                    self.set_workbench_page(WorkbenchPage::Prove);
                }
                // Open after the page transition so finding detail remains
                // focused; otherwise `set_workbench_page` resets focus to the
                // Confirm composition's primary Evidence surface.
                self.open_workbench_finding_or_log();
            }
            PhaseSurfaceId::MapReadiness => self.draft_map_action_card_command(),
            focus if focus == page.findings_surface() => self.open_workbench_finding_or_log(),
            PhaseSurfaceId::MapAttackSurface
            | PhaseSurfaceId::ScanEngines
            | PhaseSurfaceId::ProveEvidence
            | PhaseSurfaceId::FixAttackTree => self.open_workbench_focused_viz(),
            _ => {}
        }
    }

    /// Enter on the Map action drawer loads the card's threat-model action
    /// into the prompt — bootstrap when no model exists, refine when stale,
    /// otherwise the journey planner. Kuzushi recommends; the operator still
    /// presses Enter to authorize the actual run.
    fn draft_map_action_card_command(&mut self) {
        let model = crate::ui_view_models::phase_cockpit_model_for_phase(
            self,
            kuzushi_core::WorkflowPhase::Map,
        );
        let crate::ui_view_models::PhaseCockpitBody::Map(map) = model.body else {
            return;
        };
        let (command, note) = if map.dfd.empty_hint.is_some() || map.empty_hint.is_some() {
            (
                "run threat-model:build {}",
                "threat-model draft loaded — Enter to generate (seeds scan recommendations)",
            )
        } else if map.context.state.eq_ignore_ascii_case("stale") {
            (
                "run threat-model:build {}",
                "refine draft loaded — Enter to update the stale threat model",
            )
        } else {
            ("next", "journey planner loaded — Enter to continue Map")
        };
        self.set_input(command.to_string());
        self.set_input_mode(InputMode::Prompt);
        self.log("map", note);
    }

    fn open_workbench_finding_or_log(&mut self) {
        if self.findings().is_empty() {
            self.log("findings", "no findings yet — run `scan` first");
            return;
        }
        self.open_finding_at_cursor();
    }

    fn draft_workbench_validation(&mut self) -> InputUpdate {
        let Some(finding) = self.current_workbench_finding() else {
            self.log(
                "verify",
                "no finding selected — open REVIEW and choose a finding first",
            );
            return InputUpdate::handled();
        };
        let input = serde_json::json!({ "fingerprint": finding.fingerprint }).to_string();
        self.set_input(format!("run verify:exploit {input}"));
        self.set_input_mode(InputMode::Prompt);
        self.log("verify", "draft loaded — press Enter to start verification");
        InputUpdate::handled()
    }

    fn draft_workbench_proof_deferral(&mut self) -> InputUpdate {
        let Some((alias, finding)) = crate::ui_view_models::current_finding_for_detail(self) else {
            self.log("prove", "no finding selected — choose a finding first");
            return InputUpdate::handled();
        };
        let reference = alias.unwrap_or(finding.fingerprint);
        self.set_input(format!("proof defer {reference} --reason "));
        self.set_input_mode(InputMode::Prompt);
        self.log(
            "prove",
            "deferral draft loaded — enter a human reason and submit",
        );
        InputUpdate::handled()
    }

    fn draft_workbench_patch_reverification(&mut self) -> InputUpdate {
        let model = crate::ui_view_models::phase_cockpit_model_for_phase(
            self,
            kuzushi_core::WorkflowPhase::Fix,
        );
        let crate::ui_view_models::PhaseCockpitBody::Fix(fix) = model.body else {
            return InputUpdate::handled();
        };
        let Some(command) = fix.remediation.reverify_command else {
            self.log(
                "patch",
                "no applied patch receipt is eligible for re-verification",
            );
            return InputUpdate::handled();
        };
        self.set_input(command);
        self.set_input_mode(InputMode::Prompt);
        self.log(
            "patch",
            "re-verification draft loaded — press Enter to start",
        );
        InputUpdate::handled()
    }

    fn draft_workbench_suppression(&mut self) -> InputUpdate {
        let Some((alias, finding)) = crate::ui_view_models::current_finding_for_detail(self) else {
            self.log("suppress", "no finding selected — choose a finding first");
            return InputUpdate::handled();
        };
        let reference = alias.unwrap_or(finding.fingerprint);
        self.set_input(format!("suppress {reference} --reason "));
        self.set_input_mode(InputMode::Prompt);
        self.log("suppress", "draft loaded — enter a reason and submit");
        InputUpdate::handled()
    }

    /// Seed a repo-wide invariant hunt from the selected finding: the
    /// composer gets an editable `run agentic-sast:scan {"focus": …}` draft,
    /// so Enter launches through the ordinary tool runner — prereq chain,
    /// budget gates, and background events included.
    fn draft_workbench_invariant_hunt(&mut self) -> InputUpdate {
        let Some((_, finding)) = crate::ui_view_models::current_finding_for_detail(self) else {
            self.log(
                "invariant",
                "no finding selected — open REVIEW and choose a finding first",
            );
            return InputUpdate::handled();
        };
        let input = serde_json::json!({ "focus": invariant_hunt_focus(&finding) }).to_string();
        self.set_input(format!("run agentic-sast:scan {input}"));
        self.set_input_mode(InputMode::Prompt);
        self.log(
            "invariant",
            "hunt draft loaded — edit the focus hypothesis, then Enter launches a repo-wide agentic scan",
        );
        InputUpdate::handled()
    }

    fn reset_workbench_detail_scroll(&mut self) {
        let detail = crate::ui_view_models::active_workbench_page(self).detail_surface();
        self.router.workbench_mut().scroll_mut().set(detail, 0);
    }

    fn draft_workbench_chain(&mut self) -> InputUpdate {
        self.set_input("run exploit-chain:scan {}".to_string());
        self.set_input_mode(InputMode::Prompt);
        self.log(
            "chain",
            "draft loaded — press Enter to start exploit-chain analysis",
        );
        InputUpdate::handled()
    }

    /// Deterministic ledger-only counterpart to `draft_workbench_chain`:
    /// folds already-confirmed findings into chain candidates without a
    /// model call, so it is safe to run on every triage pass.
    fn draft_workbench_chain_fold(&mut self) -> InputUpdate {
        self.set_input("run findings:chains {}".to_string());
        self.set_input_mode(InputMode::Prompt);
        self.log(
            "chain",
            "draft loaded — press Enter to fold confirmed findings into chain candidates (no model)",
        );
        InputUpdate::handled()
    }

    pub(super) fn reduce_hotkey_command(&mut self, command: ShellCommand) -> InputUpdate {
        let update = self.reduce_command_message(command);
        if update.handled {
            InputUpdate::handled_with_effects(update.effects)
        } else {
            InputUpdate::ignored()
        }
    }

    fn toggle_review_backlog_preset(&mut self) {
        let review = self.router.workbench_mut().review_mut();
        review.backlog = !review.backlog;
        let enabled = review.backlog;
        let decided = review.session_decided;
        self.router.findings_mut().jump(true, 0);
        if enabled {
            self.log(
                "review",
                format!(
                    "backlog preset ON — untriaged only, severity-first; c confirm · f reject-FP · d defer · w needs-review · B off ({decided} decided this session)"
                ),
            );
        } else {
            self.log(
                "review",
                "backlog preset OFF — confidence-first order and full queue restored",
            );
        }
    }

    /// One-key backlog decision on the cursored finding. Routes through the
    /// exact `decision <verdict> <reason>` reducer so watermark checks,
    /// suppression redirects, and the pinned-finding disclosure rule all
    /// apply unchanged.
    fn apply_backlog_one_key_decision(&mut self, verdict: &'static str) -> InputUpdate {
        if !self.router.workbench().review().backlog {
            return InputUpdate::handled();
        }
        self.remember_backlog_batch_for_cursored_finding();
        self.router
            .workbench_mut()
            .review_mut()
            .backlog_confirm_bulk = false;
        let reason = format!("backlog one-key {verdict} by operator");
        let effects =
            self.reduce_review_decision_command(&crate::commands::ReviewDecisionCommand::Record {
                verdict: verdict.to_string(),
                reason,
            });
        InputUpdate {
            handled: true,
            effects,
        }
    }

    const BACKLOG_SEVERITIES: [&'static str; 4] = ["critical", "high", "medium", "low"];

    fn cycle_backlog_severity_filter(&mut self) {
        if !self.router.workbench().review().backlog {
            return;
        }
        let review = self.router.workbench_mut().review_mut();
        review.backlog_confirm_bulk = false;
        review.backlog_severity = match review.backlog_severity {
            None => Some(Self::BACKLOG_SEVERITIES[0]),
            Some(current) => Self::BACKLOG_SEVERITIES
                .iter()
                .position(|s| *s == current)
                .and_then(|index| Self::BACKLOG_SEVERITIES.get(index + 1))
                .copied(),
        };
        let label = review
            .backlog_severity
            .map(|s| format!("sev:{s}"))
            .unwrap_or_else(|| "all severities".to_string());
        self.router.findings_mut().jump(true, 0);
        self.log("review", format!("backlog filter — {label}"));
    }

    fn cycle_backlog_tool_filter(&mut self) {
        if !self.router.workbench().review().backlog {
            return;
        }
        let tools: Vec<String> = self
            .findings()
            .iter()
            .map(|finding| finding.tool.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let review = self.router.workbench_mut().review_mut();
        review.backlog_confirm_bulk = false;
        review.backlog_tool = match review.backlog_tool.take() {
            None => tools.first().cloned(),
            Some(current) => tools
                .iter()
                .position(|tool| *tool == current)
                .and_then(|index| tools.get(index + 1))
                .cloned(),
        };
        let label = review
            .backlog_tool
            .as_deref()
            .map(|tool| format!("tool:{tool}"))
            .unwrap_or_else(|| "all tools".to_string());
        self.router.findings_mut().jump(true, 0);
        self.log("review", format!("backlog filter — {label}"));
    }

    /// Bulk defer of the current filtered backlog set. First `X` arms a
    /// confirmation (shown in the header), the second executes; any other
    /// backlog action disarms — decisions are never bulk-recorded without
    /// an explicit confirm.
    fn apply_backlog_bulk_defer(&mut self) -> InputUpdate {
        if !self.router.workbench().review().backlog {
            return InputUpdate::handled();
        }
        let batch = self.visible_backlog_findings();
        if batch.is_empty() {
            self.log("review", "backlog defer-all — nothing visible to defer");
            return InputUpdate::handled();
        }
        if !self.router.workbench().review().backlog_confirm_bulk {
            self.router
                .workbench_mut()
                .review_mut()
                .backlog_confirm_bulk = true;
            self.log(
                "review",
                format!(
                    "backlog defer-all — press X again to defer {} visible finding(s), any other action cancels",
                    batch.len()
                ),
            );
            return InputUpdate::handled();
        }
        self.router
            .workbench_mut()
            .review_mut()
            .backlog_confirm_bulk = false;
        let mut effects = Vec::new();
        let mut undo_batch = Vec::new();
        for (alias, finding) in batch {
            undo_batch.push(crate::app::view_state::BacklogUndoEntry {
                finding: finding.clone(),
                alias: alias.clone(),
                prior_verdict: self.latest_verdict_str(&finding),
            });
            let decision = kuzushi_core::findings::ReviewDecision {
                verdict: kuzushi_core::findings::ReviewDecisionVerdict::Deferred,
                author: kuzushi_core::findings::TriageAuthor::Human,
                confidence: 1.0,
                rationale: "backlog bulk defer by operator".to_string(),
                dismiss_reason: None,
                actor: None,
            };
            effects.push(self.current_finding_decision_effect(alias, finding, decision));
        }
        let count = undo_batch.len();
        self.router.workbench_mut().review_mut().backlog_last_batch = undo_batch;
        self.log(
            "review",
            format!("backlog defer-all — {count} finding(s) deferred (u undoes)"),
        );
        InputUpdate {
            handled: true,
            effects,
        }
    }

    /// Single-level undo: append the inverse review record per finding in
    /// the last backlog batch (the prior latest verdict, or needs_review
    /// when the finding was undecided). History is never deleted — the
    /// latest-decision-wins fold makes the append a reversal.
    fn apply_backlog_undo(&mut self) -> InputUpdate {
        if !self.router.workbench().review().backlog {
            return InputUpdate::handled();
        }
        self.router
            .workbench_mut()
            .review_mut()
            .backlog_confirm_bulk = false;
        let batch =
            std::mem::take(&mut self.router.workbench_mut().review_mut().backlog_last_batch);
        if batch.is_empty() {
            self.log("review", "backlog undo — no decision batch to reverse");
            return InputUpdate::handled();
        }
        let mut effects = Vec::new();
        let mut restored = 0usize;
        for entry in batch {
            let Some(verdict) = self.parse_review_decision_verdict_or_log(&entry.prior_verdict)
            else {
                continue;
            };
            let decision = kuzushi_core::findings::ReviewDecision {
                verdict,
                author: kuzushi_core::findings::TriageAuthor::Human,
                confidence: 1.0,
                rationale: "backlog undo — restore prior latest decision".to_string(),
                dismiss_reason: None,
                actor: None,
            };
            effects.push(self.current_finding_decision_effect(
                entry.alias,
                entry.finding,
                decision,
            ));
            restored += 1;
        }
        self.log(
            "review",
            format!("backlog undo — {restored} inverse record(s) appended"),
        );
        InputUpdate {
            handled: true,
            effects,
        }
    }

    /// The findings currently visible under the backlog projection
    /// (untriaged + severity/tool filters), as owned rows.
    fn visible_backlog_findings(&self) -> Vec<(Option<String>, Finding)> {
        crate::ui_view_models::visible_sorted_finding_alias_indices(self)
            .into_iter()
            .filter_map(|(alias, index)| {
                self.findings()
                    .get(index)
                    .cloned()
                    .map(|finding| (Some(alias), finding))
            })
            .collect()
    }

    /// The finding's current latest review verdict, for the undo batch.
    fn latest_verdict_str(&self, finding: &Finding) -> String {
        let Some(finding_id) = finding.id else {
            return "needs_review".to_string();
        };
        self.review_decisions()
            .iter()
            .filter(|record| record.finding_id == finding_id)
            .max_by_key(|record| record.id)
            .map(|record| record.decision.verdict.as_str().to_string())
            .unwrap_or_else(|| "needs_review".to_string())
    }

    /// One-key decisions target the cursored finding; remember its prior
    /// verdict as a one-entry undo batch before the decision lands.
    fn remember_backlog_batch_for_cursored_finding(&mut self) {
        let Some(finding) = self.current_workbench_finding() else {
            return;
        };
        let prior = self.latest_verdict_str(&finding);
        self.router.workbench_mut().review_mut().backlog_last_batch =
            vec![crate::app::view_state::BacklogUndoEntry {
                alias: None,
                prior_verdict: prior,
                finding,
            }];
    }

    fn open_workbench_coverage_clusters(&mut self) {
        self.set_workbench_page(WorkbenchPage::Review);
        self.log(
            "cluster",
            "coverage groups duplicates and root-cause clusters without hiding distinct sinks",
        );
    }

    fn current_workbench_finding(&self) -> Option<Finding> {
        crate::ui_view_models::current_finding_for_detail(self).map(|(_, finding)| finding)
    }

    fn apply_scroll_hotkey(&mut self, action: ViewHotkeyAction) -> bool {
        match action {
            ViewHotkeyAction::ViewScrollUp => self.scroll_current_view_up(1),
            ViewHotkeyAction::ViewScrollDown => self.scroll_current_view_down(1),
            ViewHotkeyAction::ViewScrollTop => self.scroll_current_view_to_top(),
            ViewHotkeyAction::ViewScrollBottom => self.scroll_current_view_to_bottom(),
            ViewHotkeyAction::ViewPageUp => self.page_up_current_view(),
            ViewHotkeyAction::ViewPageDown => self.page_down_current_view(),
            _ => return false,
        }
        true
    }

    fn apply_scroll_hotkey_update(&mut self, action: ViewHotkeyAction) -> InputUpdate {
        if self.apply_scroll_hotkey(action) {
            InputUpdate::handled()
        } else {
            InputUpdate::ignored()
        }
    }

    fn apply_recommend_hotkey(&mut self, action: ViewHotkeyAction) -> InputUpdate {
        match action {
            ViewHotkeyAction::RecommendCursorPrevious => {
                self.move_recommend_cursor(-1);
                InputUpdate::handled()
            }
            ViewHotkeyAction::RecommendCursorNext => {
                self.move_recommend_cursor(1);
                InputUpdate::handled()
            }
            ViewHotkeyAction::RecommendScanComponent => self.scan_recommend_component(),
            ViewHotkeyAction::RecommendPromoteComponent => self.promote_recommend_component(),
            _ => InputUpdate::ignored(),
        }
    }

    fn move_recommend_cursor(&mut self, delta: isize) {
        let count = crate::ui_view_models::recommendation_components(self).len();
        if count == 0 {
            self.router.catalog_mut().reset_recommend_cursor();
            self.log(
                "component",
                "no component recommendations yet — run `recommend` first",
            );
            return;
        }
        self.router
            .catalog_mut()
            .move_recommend_cursor(delta, count);
    }

    fn scan_recommend_component(&mut self) -> InputUpdate {
        let Some(component) = self.selected_recommend_component() else {
            self.log(
                "component",
                "no component selected — run `recommend` to rank components first",
            );
            return InputUpdate::handled();
        };
        self.log(
            "component",
            format!(
                "scanning {} as {} within the current target",
                component.rel_path, component.class_label
            ),
        );
        self.reduce_hotkey_command(ShellCommand::RunTool {
            tool: Some("sast:scan".to_string()),
            input: component.scan_input.clone(),
        })
    }

    fn promote_recommend_component(&mut self) -> InputUpdate {
        let Some(component) = self.selected_recommend_component() else {
            self.log(
                "component",
                "no component selected — run `recommend` to rank components first",
            );
            return InputUpdate::handled();
        };
        if component.promote_command.is_none() {
            self.log(
                "component",
                format!(
                    "{} is best scanned inside the current target",
                    component.rel_path
                ),
            );
            return InputUpdate::handled();
        }
        let Some(target_path) = self.recommend_component_target_path(&component.rel_path) else {
            self.log(
                "component",
                "promotion needs an active target and target-relative component path",
            );
            return InputUpdate::handled();
        };
        let effects = self.request_target_activation(TargetActivation {
            path: target_path,
            selected_scope: None,
            source: TargetActivationSource::Command,
        });
        if effects.is_empty() {
            return InputUpdate::handled();
        }
        self.log(
            "component",
            format!("promoted {} to its own target", component.rel_path),
        );
        InputUpdate::handled_with_effects(effects)
    }

    fn selected_recommend_component(
        &mut self,
    ) -> Option<crate::ui_view_models::ComponentRecommendationRow> {
        let components = crate::ui_view_models::recommendation_components(self);
        let selected = self
            .router
            .catalog_mut()
            .selected_recommend_cursor(components.len());
        components.get(selected).cloned()
    }

    fn recommend_component_target_path(&self, rel_path: &str) -> Option<PathBuf> {
        let target = self.target_path_buf()?;
        let rel = Self::target_relative_component_path(rel_path)?;
        Some(target.join(rel))
    }

    fn target_relative_component_path(rel_path: &str) -> Option<PathBuf> {
        let trimmed = rel_path.trim_matches('/');
        let path = Path::new(trimmed);
        let relative = !trimmed.is_empty()
            && path
                .components()
                .all(|component| matches!(component, Component::Normal(_)));
        relative.then(|| path.to_path_buf())
    }

    fn apply_prompt_or_tune_hotkey(&mut self, action: ViewHotkeyAction) -> InputUpdate {
        match action {
            ViewHotkeyAction::TuneCursorPrevious => {
                self.move_tune_cursor(-1);
                InputUpdate::handled()
            }
            ViewHotkeyAction::TuneCursorNext => {
                self.move_tune_cursor(1);
                InputUpdate::handled()
            }
            ViewHotkeyAction::TuneActivate => {
                InputUpdate::handled_with_effects(self.activate_tune_action())
            }
            ViewHotkeyAction::PromptsCursorPrevious => {
                self.move_prompts_cursor(-1);
                InputUpdate::handled()
            }
            ViewHotkeyAction::PromptsCursorNext => {
                self.move_prompts_cursor(1);
                InputUpdate::handled()
            }
            ViewHotkeyAction::PromptsAction(action) => {
                InputUpdate::handled_with_effects(self.activate_prompts_action(action))
            }
            _ => InputUpdate::ignored(),
        }
    }

    fn apply_actor_hotkey(&mut self, action: ViewHotkeyAction) -> bool {
        match action {
            ViewHotkeyAction::ActorDetail(index) => {
                self.router.actor_detail_mut().open(index);
                self.set_shell_view(ShellView::ActorDetail);
            }
            ViewHotkeyAction::ActorDetailFilterCycle => {
                self.router.actor_detail_mut().cycle_filter();
            }
            ViewHotkeyAction::ActorDetailFilterReset => {
                self.router.actor_detail_mut().reset_filter();
            }
            _ => return false,
        }
        true
    }

    fn apply_actor_hotkey_update(&mut self, action: ViewHotkeyAction) -> InputUpdate {
        if self.apply_actor_hotkey(action) {
            InputUpdate::handled()
        } else {
            InputUpdate::ignored()
        }
    }

    fn apply_shell_hotkey(&mut self, action: ViewHotkeyAction) -> InputUpdate {
        if self.apply_activity_hotkey(action) {
            return InputUpdate::handled();
        }
        match action {
            ViewHotkeyAction::CatalogActivate => self.load_catalog_action(),
            ViewHotkeyAction::CatalogToggleExpert => self.toggle_catalog_expert(),
            ViewHotkeyAction::ThreatView(view) => {
                self.router.threat_mut().open(view);
                self.set_shell_view(ShellView::Threat);
                InputUpdate::handled()
            }
            ViewHotkeyAction::PauseScan => self.reduce_hotkey_command(ShellCommand::Pause),
            ViewHotkeyAction::ResumeScan => self.reduce_hotkey_command(ShellCommand::Resume(None)),
            ViewHotkeyAction::OpenNextPhase => self.reduce_hotkey_command(ShellCommand::Next),
            ViewHotkeyAction::Back => {
                self.go_back();
                InputUpdate::handled()
            }
            _ => InputUpdate::ignored(),
        }
    }

    fn load_catalog_action(&mut self) -> InputUpdate {
        if self.target().is_none() {
            self.open_target_picker();
            return InputUpdate::handled();
        }
        let Some(command) = self.catalog_cursor_command() else {
            self.log("capability", "no capability action is available");
            return InputUpdate::handled();
        };
        self.set_input(command.clone());
        self.set_input_mode(InputMode::Prompt);
        self.log(
            "capability",
            format!("loaded `{}` — edit if needed, then submit", command.trim()),
        );
        InputUpdate::handled()
    }

    fn toggle_catalog_expert(&mut self) -> InputUpdate {
        self.router.catalog_mut().toggle_expanded();
        let message = if self.router.catalog().is_expanded() {
            "showing expert engines and installed integrations"
        } else {
            "showing phase-native actions"
        };
        self.log("capability", message);
        InputUpdate::handled()
    }

    fn apply_activity_hotkey(&mut self, action: ViewHotkeyAction) -> bool {
        if self.apply_activity_session_hotkey(action) {
            return true;
        }
        match action {
            ViewHotkeyAction::ActivityReset => self.reset_activity_view(),
            ViewHotkeyAction::ActivityFocusSelected => self.open_or_focus_activity_task(),
            ViewHotkeyAction::ActivityBackground => self.background_handoff(),
            ViewHotkeyAction::ActivitySteer => self.open_run_focus_steer_editor(),
            _ => return false,
        }
        true
    }

    fn apply_activity_session_hotkey(&mut self, action: ViewHotkeyAction) -> bool {
        if matches!(action, ViewHotkeyAction::ActivityTabPaneFocus)
            && self
                .activity()
                .is_some_and(|session| session.tasks.is_empty())
        {
            self.log(
                "activity",
                "no task rows to focus; output is already full width",
            );
            return true;
        }
        let Some(session) = self.activity() else {
            return false;
        };
        let event_count = if session.run_projection.timeline.is_empty() {
            session.events.len()
        } else {
            session.run_projection.timeline.len()
        };
        let route = self.router.activity_mut();
        match action {
            ViewHotkeyAction::ActivityTabPaneFocus => route.toggle_pane_focus(),
            ViewHotkeyAction::ActivityToggleVerbose => route.toggle_verbose_subsystems(),
            ViewHotkeyAction::ActivityTogglePause => route.toggle_paused(event_count),
            _ => return false,
        };
        true
    }

    fn reset_activity_view(&mut self) {
        if self.activity().is_none() {
            self.log("activity", "no Activity view state to reset");
            return;
        }
        self.router.activity_mut().reset_presentation_state();
        self.log("activity", "reset Activity view state; run preserved");
    }

    fn open_run_focus_steer_editor(&mut self) {
        if !self.has_running_work() {
            self.log("steer", "no live run to steer");
            return;
        }
        self.router.activity_mut().open_steer_editor();
        self.set_input_mode(InputMode::Navigate);
    }

    fn open_or_focus_activity_task(&mut self) {
        let Some(task_id) = self.focus_activity_task_at_cursor() else {
            self.log_activity_focus_unavailable();
            return;
        };
        self.log("activity", format!("focused run step {task_id}"));
    }

    fn log_activity_focus_unavailable(&mut self) {
        let message = match self.activity() {
            None => "no active run to focus",
            Some(session) if session.tasks.is_empty() => {
                "no task rows to focus; output is already full width"
            }
            Some(_) => "no visible task at the current cursor",
        };
        self.log("activity", message);
    }

    fn focus_activity_task_at_cursor(&mut self) -> Option<String> {
        let session = self.activity()?;
        if session.tasks.is_empty() {
            return None;
        }
        let task_id = self
            .router
            .activity()
            .task_id_at_cursor(session)?
            .to_string();
        self.router.activity_mut().focus_task = Some(task_id.clone());
        Some(task_id)
    }
}

/// The hunt-focus hypothesis seeded from a finding: names the reference
/// violation and asks for repo-wide siblings, so it stays useful even when
/// the operator submits it unedited.
fn invariant_hunt_focus(finding: &kuzushi_core::Finding) -> String {
    format!(
        "Invariant hunt seeded from {} at {}:{}. Reference violation: {}. \
         Hunt the whole repository for other code that violates the same \
         invariant and report each site with file:line evidence.",
        finding.rule_id, finding.file_path, finding.start_line, finding.title
    )
}

fn current_phase_plan(app: &ShellApp) -> Option<crate::ui_view_models::PhasePresentationPlan> {
    let viewport = app.viewport();
    crate::renderer::workbench_phase_plan_for_app(
        app,
        ratatui::layout::Rect::new(0, 0, viewport.columns, viewport.rows),
    )
}

fn effective_phase_surface(app: &ShellApp) -> Option<crate::ui_view_models::PlannedPhaseSurface> {
    let plan = current_phase_plan(app)?;
    plan.surface(plan.effective_focus).copied()
}

fn cycle_index(current: usize, count: usize, reverse: bool) -> usize {
    if count == 0 {
        return 0;
    }
    if reverse {
        (current + count - 1) % count
    } else {
        (current + 1) % count
    }
}

fn focused_workbench_visualization(
    surface: crate::ui_view_models::PhaseSurfaceId,
) -> FocusedWorkbenchVisualization {
    use crate::ui_view_models::PhaseSurfaceId;
    match surface {
        PhaseSurfaceId::MapReadiness | PhaseSurfaceId::MapAttackSurface => {
            FocusedWorkbenchVisualization::Scene(VizPage::AttackSurface)
        }
        PhaseSurfaceId::MapHotModules
        | PhaseSurfaceId::ScanEngines
        | PhaseSurfaceId::ScanReceipt
        | PhaseSurfaceId::ScanDelta
        | PhaseSurfaceId::ScanScope
        | PhaseSurfaceId::ReviewQueue
        | PhaseSurfaceId::ReviewDetail => FocusedWorkbenchVisualization::Scene(VizPage::Heatmap),
        PhaseSurfaceId::MapDfd | PhaseSurfaceId::FixRemediation | PhaseSurfaceId::FixDfd => {
            FocusedWorkbenchVisualization::Scene(VizPage::Dfd)
        }
        PhaseSurfaceId::ProveStatus
        | PhaseSurfaceId::ProveEvidence
        | PhaseSurfaceId::ProveLadder
        | PhaseSurfaceId::ProveNextAction => {
            FocusedWorkbenchVisualization::Scene(VizPage::AttackPath)
        }
        PhaseSurfaceId::ProveReceipt => FocusedWorkbenchVisualization::ProofReplay,
        PhaseSurfaceId::FixCandidate
        | PhaseSurfaceId::FixVerification
        | PhaseSurfaceId::FixAttackTree => {
            FocusedWorkbenchVisualization::Scene(VizPage::ExploitChain)
        }
    }
}

#[cfg(test)]
mod invariant_hunt_focus_tests {
    use super::*;

    #[test]
    fn seed_names_the_rule_location_and_reference_violation() {
        let finding = kuzushi_core::Finding::new_tool(
            "semgrep",
            "rules.cwe-787",
            "src/compress.c",
            108,
            None,
            kuzushi_core::findings::Severity::High,
            "dst_len truncation before SDDecompress",
        );

        let focus = invariant_hunt_focus(&finding);

        assert!(
            focus.starts_with("Invariant hunt seeded from rules.cwe-787 at src/compress.c:108."),
            "{focus}"
        );
        assert!(focus.contains("dst_len truncation before SDDecompress"), "{focus}");
        assert!(focus.contains("Hunt the whole repository"), "{focus}");
    }
}

#[cfg(test)]
mod phase_visualization_tests {
    use super::*;

    fn assert_visualization(
        surface: crate::ui_view_models::PhaseSurfaceId,
        expected: FocusedWorkbenchVisualization,
    ) {
        assert_eq!(focused_workbench_visualization(surface), expected);
    }

    #[test]
    fn map_and_review_panes_open_phase_native_scenes() {
        assert_visualization(
            crate::ui_view_models::PhaseSurfaceId::MapAttackSurface,
            FocusedWorkbenchVisualization::Scene(VizPage::AttackSurface),
        );
        for surface in [
            crate::ui_view_models::PhaseSurfaceId::ReviewQueue,
            crate::ui_view_models::PhaseSurfaceId::ReviewDetail,
        ] {
            assert_visualization(
                surface,
                FocusedWorkbenchVisualization::Scene(VizPage::Heatmap),
            );
        }
    }

    #[test]
    fn prove_flow_and_proof_panes_have_distinct_destinations() {
        for surface in [
            crate::ui_view_models::PhaseSurfaceId::ProveStatus,
            crate::ui_view_models::PhaseSurfaceId::ProveEvidence,
            crate::ui_view_models::PhaseSurfaceId::ProveLadder,
        ] {
            assert_visualization(
                surface,
                FocusedWorkbenchVisualization::Scene(VizPage::AttackPath),
            );
        }
        assert_visualization(
            crate::ui_view_models::PhaseSurfaceId::ProveReceipt,
            FocusedWorkbenchVisualization::ProofReplay,
        );
    }

    #[test]
    fn fix_tree_and_dfd_panes_open_matching_scenes() {
        for surface in [
            crate::ui_view_models::PhaseSurfaceId::FixCandidate,
            crate::ui_view_models::PhaseSurfaceId::FixAttackTree,
        ] {
            assert_visualization(
                surface,
                FocusedWorkbenchVisualization::Scene(VizPage::ExploitChain),
            );
        }
        for surface in [
            crate::ui_view_models::PhaseSurfaceId::FixRemediation,
            crate::ui_view_models::PhaseSurfaceId::FixDfd,
        ] {
            assert_visualization(surface, FocusedWorkbenchVisualization::Scene(VizPage::Dfd));
        }
    }
}

type FocusedHotkeyHandler = fn(&mut ShellApp, ViewHotkeyAction) -> InputUpdate;

const FOCUSED_HOTKEY_HANDLERS: &[FocusedHotkeyHandler] = &[
    ShellApp::apply_scroll_hotkey_update,
    ShellApp::apply_recommend_hotkey,
    ShellApp::apply_prompt_or_tune_hotkey,
    ShellApp::apply_actor_hotkey_update,
    ShellApp::apply_campaign_hotkey,
];
