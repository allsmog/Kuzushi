use super::*;
use crate::commands::ReviewDecisionCommand;
use kuzushi_core::findings::{
    DismissReason, Finding, ReviewDecision, ReviewDecisionVerdict, TriageAuthor,
};

impl ShellApp {
    pub(crate) fn reduce_review_decision_command(
        &mut self,
        command: &ReviewDecisionCommand,
    ) -> Vec<ShellEffect> {
        match command {
            ReviewDecisionCommand::Record { verdict, reason } => {
                self.reduce_current_finding_review_decision(verdict, reason)
            }
            ReviewDecisionCommand::Dismiss { reason, note } => {
                self.reduce_current_finding_dismissal(reason, note)
            }
            ReviewDecisionCommand::Suppress {
                reference,
                reason,
                author,
                days,
            } => vec![ShellEffect::RecordSuppression(SuppressionApply {
                target: self.target_owned(),
                reference: reference.clone(),
                reason: reason.clone(),
                author: author.clone(),
                days: *days,
            })],
            ReviewDecisionCommand::Unsupported(raw) => {
                self.set_warn_notice(
                    "review",
                    format!(
                        "unsupported review command `{raw}`. Next: decision <verdict> <reason> | dismiss <reason> <note>"
                    ),
                );
                Vec::new()
            }
        }
    }

    fn reduce_current_finding_review_decision(
        &mut self,
        verdict: &str,
        reason: &str,
    ) -> Vec<ShellEffect> {
        let Some(verdict) = self.parse_review_decision_verdict_or_log(verdict) else {
            return Vec::new();
        };
        let Some(reason) = self.non_empty_review_decision_reason_or_log(reason) else {
            return Vec::new();
        };
        let Some((alias, finding)) = self.current_review_finding_or_log() else {
            return Vec::new();
        };
        if verdict == ReviewDecisionVerdict::Suppressed {
            return vec![self.default_suppression_effect(alias, &finding, reason)];
        }
        let decision = ReviewDecision {
            verdict,
            author: TriageAuthor::Human,
            confidence: 1.0,
            rationale: reason,
            dismiss_reason: None,
            actor: None,
        };
        vec![self.current_finding_decision_effect(alias, finding, decision)]
    }

    fn default_suppression_effect(
        &self,
        alias: Option<String>,
        finding: &Finding,
        reason: String,
    ) -> ShellEffect {
        ShellEffect::RecordSuppression(SuppressionApply {
            target: self.target_owned(),
            reference: alias.unwrap_or_else(|| finding.fingerprint.clone()),
            reason,
            author: "operator".to_string(),
            days: 90,
        })
    }

    fn current_finding_decision_effect(
        &self,
        alias: Option<String>,
        finding: Finding,
        decision: ReviewDecision,
    ) -> ShellEffect {
        let read_watermark = self
            .router
            .workbench()
            .review()
            .read_watermark_for(finding_stable_fp(&finding))
            .or_else(|| self.findings_read_watermark_for(&finding));
        ShellEffect::RecordReviewDecision(ReviewDecisionApply {
            alias,
            decision,
            finding,
            read_watermark,
            target: self.target_owned(),
        })
    }

    pub(crate) fn record_suppression_effect(
        &mut self,
        apply: SuppressionApply,
    ) -> Vec<ShellEffect> {
        let Some(target) = apply.target.as_deref() else {
            self.set_error_notice("suppress", "suppress needs an active target");
            return Vec::new();
        };
        let workspace = match WorkspaceTarget::new(target) {
            Ok(workspace) => workspace,
            Err(error) => {
                self.set_error_notice(
                    "suppress",
                    format!("could not open suppression workspace: {error}"),
                );
                return Vec::new();
            }
        };
        match self.persist_suppression(&workspace, &apply) {
            Ok((message, fingerprint)) => {
                self.set_success_notice("suppress", message);
                let filter = self.active_findings_filter();
                let mut effects = vec![ShellEffect::RefreshFindings(FindingsRefresh {
                    announce: false,
                    filter: filter.clone(),
                })];
                if filter.is_some() {
                    effects.push(ShellEffect::ReportFilteredFindingMovement(
                        FilteredFindingMovementNotice { fingerprint },
                    ));
                }
                effects
            }
            Err(error) => {
                self.set_error_notice("suppress", format!("suppression not recorded: {error}"));
                Vec::new()
            }
        }
    }

    fn persist_suppression(
        &self,
        workspace: &WorkspaceTarget,
        apply: &SuppressionApply,
    ) -> anyhow::Result<(String, String)> {
        let store = kuzushi_core::FindingStore::open(workspace.findings_db_path())?;
        let report = store.list_findings_filtered(&kuzushi_core::FindingListFilter::with_limit(
            kuzushi_core::FindingListFilter::MAX_LIMIT,
        ))?;
        let finding = kuzushi_core::resolve_finding_alias(&report.findings, &apply.reference)
            .or(store.get_finding_by_reference(&apply.reference)?)
            .ok_or_else(|| anyhow::anyhow!("no finding matches {:?}", apply.reference))?;
        let expires_at_unix = current_unix().saturating_add(apply.days.saturating_mul(86_400));
        let result = kuzushi_core::suppressions::record_finding_suppression(
            workspace,
            &finding,
            kuzushi_core::suppressions::FindingSuppressionRequest {
                reason: apply.reason.clone(),
                author: apply.author.clone(),
                expires_at_unix,
            },
        )?;
        Ok((
            format!(
                "recorded {} for {} · decision #{} · expires in {} days{}",
                result.record.id,
                apply.reference,
                result.decision_id,
                apply.days,
                if result.structured_rule_written {
                    ""
                } else {
                    " · free-text reason saved without a structured rule"
                }
            ),
            finding.fingerprint,
        ))
    }

    fn findings_read_watermark_for(&self, finding: &Finding) -> Option<u64> {
        let stable_fp = finding_stable_fp(finding);
        self.findings()
            .iter()
            .any(|row| finding_stable_fp(row) == stable_fp)
            .then(|| self.findings_read_watermark())
            .flatten()
    }

    fn reduce_current_finding_dismissal(&mut self, reason: &str, note: &str) -> Vec<ShellEffect> {
        let Some(reason) = self.parse_dismiss_reason_or_log(reason) else {
            return Vec::new();
        };
        let Some(note) = self.non_empty_review_decision_reason_or_log(note) else {
            return Vec::new();
        };
        let Some((alias, finding)) = self.current_review_finding_or_log() else {
            return Vec::new();
        };
        let decision = ReviewDecision::dismissal(reason, &note, "operator");
        let read_watermark = self
            .router
            .workbench()
            .review()
            .read_watermark_for(finding_stable_fp(&finding));
        vec![ShellEffect::RecordReviewDecision(ReviewDecisionApply {
            alias,
            decision,
            finding,
            read_watermark,
            target: self.target_owned(),
        })]
    }

    fn parse_dismiss_reason_or_log(&mut self, value: &str) -> Option<DismissReason> {
        let reason = DismissReason::from_str(value);
        if reason.is_none() {
            self.set_warn_notice(
                "review",
                format!(
                    "unknown dismissal reason `{value}`. Next: dismiss false_positive|acceptable_risk|wont_fix|used_in_tests|no_time_to_fix <note>"
                ),
            );
        }
        reason
    }

    fn parse_review_decision_verdict_or_log(
        &mut self,
        value: &str,
    ) -> Option<ReviewDecisionVerdict> {
        let verdict = parse_review_decision_verdict(value);
        if verdict.is_none() {
            self.set_warn_notice(
                "review",
                format!(
                    "unknown review decision `{value}`. Next: decision confirmed|rejected_false_positive|suppressed|deferred|accepted_risk|needs_review <reason>"
                ),
            );
        }
        verdict
    }

    fn non_empty_review_decision_reason_or_log(&mut self, value: &str) -> Option<String> {
        let reason = value.trim();
        if reason.is_empty() {
            self.set_warn_notice(
                "review",
                "review decision reason cannot be empty. Next: decision <verdict> <reason>",
            );
            return None;
        }
        Some(reason.to_string())
    }

    fn current_review_finding_or_log(&mut self) -> Option<(Option<String>, Finding)> {
        let finding = crate::ui_view_models::current_finding_for_detail(self);
        if finding.is_none() {
            self.set_warn_notice(
                "review",
                "no finding selected. Next: findings, move to a row, then decision <verdict> <reason>",
            );
        }
        finding
    }

    pub(crate) fn log_saved_review_decision(
        &mut self,
        decision_id: i64,
        verdict: ReviewDecisionVerdict,
        label: &str,
    ) {
        self.set_success_notice(
            "review",
            format!(
                "decision saved; will carry forward as decision #{decision_id} ({} for {label})",
                verdict.as_str()
            ),
        );
    }

    pub(crate) fn log_review_decision_write_error(
        &mut self,
        finding: &Finding,
        error: anyhow::Error,
    ) -> bool {
        let message = error.to_string();
        let conflicted = self.mark_review_decision_conflict_if_stale(finding, &message);
        self.set_error_notice(
            "review",
            with_next_step(
                format!("could not save review decision: {message}"),
                "open a persisted finding, then retry decision <verdict> <reason>",
            ),
        );
        conflicted
    }

    fn mark_review_decision_conflict_if_stale(&mut self, finding: &Finding, message: &str) -> bool {
        if !message.contains("changed after read watermark") {
            return false;
        }
        self.router.workbench_mut().review_mut().mode = ReviewMode::Conflict {
            message: message.to_string(),
            target_fp: finding_stable_fp(finding).to_string(),
        };
        true
    }

    pub(crate) fn clear_review_decision_conflict(&mut self) {
        if matches!(
            &self.router.workbench().review().mode,
            ReviewMode::Conflict { .. }
        ) {
            self.router.workbench_mut().review_mut().mode = ReviewMode::Browse;
        }
    }

    pub(crate) fn review_decision_conflict_refresh_effects(&mut self) -> Vec<ShellEffect> {
        vec![ShellEffect::RefreshFindings(FindingsRefresh {
            announce: false,
            filter: self.active_findings_filter().clone(),
        })]
    }

    pub(crate) fn review_decision_refresh_effects(
        &mut self,
        previous_finding: &Finding,
    ) -> Vec<ShellEffect> {
        let fingerprint = previous_finding.fingerprint.clone();
        let active_filter = self.active_findings_filter().clone();
        match active_filter {
            Some(expression) => vec![
                ShellEffect::RefreshFindings(FindingsRefresh {
                    announce: true,
                    filter: Some(expression),
                }),
                ShellEffect::ReportFilteredFindingMovement(FilteredFindingMovementNotice {
                    fingerprint,
                }),
            ],
            None => vec![ShellEffect::RefreshFindings(FindingsRefresh {
                announce: false,
                filter: None,
            })],
        }
    }

    pub(crate) fn report_filtered_finding_movement_effect(
        &mut self,
        notice: FilteredFindingMovementNotice,
    ) {
        if !self
            .findings()
            .iter()
            .any(|finding| finding.fingerprint == notice.fingerprint)
        {
            self.log("review", "row moved because the active filter excludes it");
        }
    }
}

fn current_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(crate) fn finding_stable_fp(finding: &Finding) -> &str {
    finding
        .identity_id
        .as_deref()
        .unwrap_or(finding.fingerprint.as_str())
}

fn parse_review_decision_verdict(value: &str) -> Option<ReviewDecisionVerdict> {
    let normalized = value.trim().replace('-', "_");
    let canonical = match normalized.as_str() {
        "false_positive" | "fp" => "rejected_false_positive",
        "true_positive" | "valid" => "confirmed",
        _ => normalized.as_str(),
    };
    ReviewDecisionVerdict::from_str(canonical)
}

pub(crate) fn review_decision_finding_label(alias: Option<&str>, finding: &Finding) -> String {
    alias
        .map(str::to_string)
        .unwrap_or_else(|| finding.fingerprint.chars().take(12).collect())
}
