use super::*;

impl ShellApp {
    pub(crate) fn open_finding_effects(&mut self, reference: &str) -> Vec<ShellEffect> {
        let open = ShellEffect::OpenFinding(OpenFindingReference {
            reference: reference.to_string(),
        });
        if parse_finding_alias(reference).is_some() {
            return vec![
                ShellEffect::RefreshFindings(FindingsRefresh {
                    announce: false,
                    filter: self.active_findings_filter().clone(),
                }),
                open,
            ];
        }
        vec![open]
    }

    pub(crate) fn resolve_open_finding_effect(
        &mut self,
        open: OpenFindingReference,
    ) -> Vec<ShellEffect> {
        let finalized = self.resolve_open_finding(open.reference);
        if let Some(anchor) = self.page_anchor_for_explicit_open(&finalized) {
            self.runtime_state.requested_findings_page =
                Some(kuzushi_core::findings::FindingPageRequest {
                    anchor: Some(anchor),
                    order: kuzushi_core::findings::FindingPageOrder::Confidence,
                    ..Default::default()
                });
            return vec![
                ShellEffect::RefreshFindings(FindingsRefresh {
                    announce: false,
                    filter: None,
                }),
                ShellEffect::FinalizeOpenFinding(finalized),
            ];
        }
        vec![ShellEffect::FinalizeOpenFinding(finalized)]
    }

    fn page_anchor_for_explicit_open(&self, open: &OpenFindingFinalize) -> Option<String> {
        if !self.explicit_open_can_load_page() {
            return None;
        }
        let OpenFindingOutcome::Found(finding) = &open.outcome else {
            return None;
        };
        let anchor = kuzushi_core::findings::finding_page_anchor(finding);
        (!self
            .findings()
            .iter()
            .any(|loaded| kuzushi_core::findings::finding_page_anchor(loaded) == anchor))
        .then_some(anchor)
    }

    fn explicit_open_can_load_page(&self) -> bool {
        self.active_findings_filter().is_none() && self.domain().findings_page().is_some()
    }

    pub(crate) fn finalize_open_finding_effect(
        &mut self,
        open: OpenFindingFinalize,
    ) -> Vec<ShellEffect> {
        match open.outcome {
            OpenFindingOutcome::Found(finding) => {
                let effects = self.apply_found_finding(finding);
                self.bind_selected_finding_reference(open.reference);
                return effects;
            }
            OpenFindingOutcome::ChainAlias(chain) => self.log_opened_chain_alias(&chain),
            OpenFindingOutcome::Missing => self.log_missing_finding(&open.reference),
            OpenFindingOutcome::MissingChainAlias { alias } => self.log_missing_chain_alias(alias),
            OpenFindingOutcome::MissingFindingAlias { alias } => {
                self.log_missing_finding_alias(alias)
            }
            OpenFindingOutcome::Error(error) => self.log_open_finding_error(error),
        }
        Vec::new()
    }

    fn resolve_open_finding(&self, reference: String) -> OpenFindingFinalize {
        let outcome = self.open_finding_outcome(&reference);
        OpenFindingFinalize { reference, outcome }
    }

    fn open_finding_outcome(&self, reference: &str) -> OpenFindingOutcome {
        if let Some(outcome) = self.chain_alias_outcome(reference) {
            return outcome;
        }
        if parse_finding_alias(reference).is_some() {
            return self.ledger_alias_outcome(reference);
        }
        self.finding_lookup_outcome(reference)
    }

    fn ledger_alias_outcome(&self, reference: &str) -> OpenFindingOutcome {
        let loaded = self
            .finding_aliases()
            .iter()
            .position(|alias| alias == reference)
            .and_then(|index| self.findings().get(index))
            .cloned();
        if let Some(finding) = loaded {
            return OpenFindingOutcome::Found(finding);
        }
        let result = open_finding_store_for_target_read_only(self.target_path_buf()).and_then(
            |(_, store)| {
                store.finding_for_alias_with_identity_policy(reference, self.identity_fold_policy())
            },
        );
        match result {
            Ok(Some(finding)) => OpenFindingOutcome::Found(finding),
            Ok(None) => OpenFindingOutcome::MissingFindingAlias {
                alias: reference.to_owned(),
            },
            Err(error) => OpenFindingOutcome::Error(error.to_string()),
        }
    }

    fn chain_alias_outcome(&self, reference: &str) -> Option<OpenFindingOutcome> {
        let index = parse_chain_alias(reference)?;
        Some(
            self.chain_aliases()
                .get(index)
                .cloned()
                .map(OpenFindingOutcome::ChainAlias)
                .unwrap_or_else(|| OpenFindingOutcome::MissingChainAlias {
                    alias: format_chain_alias(index),
                }),
        )
    }

    fn finding_lookup_outcome(&self, reference: &str) -> OpenFindingOutcome {
        match finding_by_reference_for_target(self.target_path_buf(), reference) {
            Ok(Some(finding)) => OpenFindingOutcome::Found(finding),
            Ok(None) => OpenFindingOutcome::Missing,
            Err(error) => OpenFindingOutcome::Error(error.to_string()),
        }
    }

    /// `open <ref>` resolved to a finding. Like Enter on the queue, this is a
    /// substantive open and starts a review session.
    fn apply_found_finding(&mut self, finding: Finding) -> Vec<ShellEffect> {
        let from_relationships = self.shell_view() == ShellView::Relationships
            && self.input_mode() == InputMode::Navigate;
        *self.selected_finding_mut() = Some(finding.clone());
        self.sync_findings_cursor_to_selected();
        self.set_shell_view(ShellView::Workbench);
        if from_relationships {
            self.set_input_mode(InputMode::Navigate);
        }
        self.router
            .workbench_mut()
            .set_page(Some(crate::app::WorkbenchPage::Review));
        self.focus_workbench_details_for_opened_finding();
        let effects = self.review_session_start_effects(&finding);
        self.log_opened_finding(&finding);
        effects
    }

    fn log_opened_chain_alias(&mut self, chain: &ExploitChain) {
        self.log(
            "open",
            format!(
                "chain {} ({}) — {}",
                chain.id,
                chain.severity.label(),
                chain.title
            ),
        );
    }

    fn log_opened_finding(&mut self, finding: &Finding) {
        self.log(
            "open",
            format!(
                "{} {}:{} {}",
                finding.severity.as_str(),
                finding.file_path,
                finding.start_line,
                finding.fingerprint
            ),
        );
        self.log("title", finding.title.clone());
        if let Some(triage) = &finding.triage {
            self.log(
                "triage",
                format!(
                    "{} {:.2} {}",
                    triage.verdict.as_str(),
                    triage.confidence,
                    triage.rationale
                ),
            );
        }
    }

    fn log_missing_finding(&mut self, reference: &str) {
        self.log(
            "error",
            format!("no finding matches {reference:?}. Next: findings or scan"),
        );
    }

    fn log_missing_chain_alias(&mut self, alias: String) {
        self.log(
            "error",
            format!("no chain alias {alias} is available. Next: /show aliases"),
        );
    }

    fn log_missing_finding_alias(&mut self, alias: String) {
        self.log(
            "error",
            format!("no finding alias {alias} is available. Next: findings"),
        );
    }

    fn log_open_finding_error(&mut self, error: String) {
        self.log("error", with_next_step(error, "findings or full <target>"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{Severity, V2Config};

    fn finding() -> Finding {
        Finding::new_semgrep(
            "demo.rule",
            "src/app.rs",
            7,
            None,
            Severity::High,
            "selected finding",
        )
    }

    #[test]
    fn alias_refresh_carries_the_active_filter() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_active_findings_filter(Some("rank:high".to_string()));

        let effects = app.open_finding_effects("F-0001");

        assert!(matches!(
            effects.as_slice(),
            [
                ShellEffect::RefreshFindings(FindingsRefresh {
                    filter: Some(expression),
                    ..
                }),
                ShellEffect::OpenFinding(_)
            ] if expression == "rank:high"
        ));
    }

    #[test]
    fn successful_open_stays_on_review_with_selected_details() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let selected = finding();
        app.set_findings(vec![selected.clone()]);
        app.set_shell_view(ShellView::Workbench);
        app.router
            .workbench_mut()
            .set_page(Some(crate::app::WorkbenchPage::Review));
        app.router
            .workbench_mut()
            .set_focus(crate::ui_view_models::PhaseSurfaceId::ReviewQueue);

        app.finalize_open_finding_effect(OpenFindingFinalize {
            reference: "F-0001".to_string(),
            outcome: OpenFindingOutcome::Found(selected),
        });

        assert_eq!(
            app.router.workbench().page(),
            Some(crate::app::WorkbenchPage::Review)
        );
        assert_eq!(
            app.router
                .workbench()
                .focus_for(crate::app::WorkbenchPage::Review),
            crate::ui_view_models::PhaseSurfaceId::ReviewDetail
        );
        let model = crate::ui_view_models::phase_cockpit_model_for_phase(
            &app,
            crate::app::WorkflowPhase::Review,
        );
        let crate::ui_view_models::PhaseCockpitBody::Review(review) = model.body else {
            panic!("open must render the Review composition");
        };
        assert_eq!(
            review.finding.as_ref().map(|detail| detail.title.as_str()),
            Some("selected finding")
        );
    }

    #[test]
    fn missing_alias_from_workbench_surfaces_actionable_notice() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::Workbench);

        app.finalize_open_finding_effect(OpenFindingFinalize {
            reference: "F-9999".to_string(),
            outcome: OpenFindingOutcome::MissingFindingAlias {
                alias: "F-9999".to_string(),
            },
        });

        let notice = app.advisory().notice.as_ref().expect("visible notice");
        assert_eq!(notice.severity, NoticeSeverity::Error);
        assert!(notice.message.contains("no finding alias F-9999"));
        assert!(notice.message.contains("Next: findings"));
    }
}
