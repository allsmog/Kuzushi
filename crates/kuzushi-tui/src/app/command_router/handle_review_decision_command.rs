use super::*;
use crate::commands::ReviewDecisionCommand;
use kuzushi_core::findings::{Finding, ReviewDecision, ReviewDecisionVerdict, TriageAuthor};

impl ShellApp {
    pub(crate) fn reduce_review_decision_command(
        &mut self,
        command: &ReviewDecisionCommand,
    ) -> Vec<ShellEffect> {
        match command {
            ReviewDecisionCommand::Record { verdict, reason } => {
                self.reduce_current_finding_review_decision(verdict, reason)
            }
            ReviewDecisionCommand::Unsupported(raw) => {
                self.log(
                    "review",
                    format!(
                        "unsupported review command `{raw}`. Next: decision <verdict> <reason>"
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
        let decision = ReviewDecision {
            verdict,
            author: TriageAuthor::Human,
            confidence: 1.0,
            rationale: reason,
        };
        let read_watermark = self
            .router
            .workbench()
            .review()
            .read_watermark_for(finding_stable_fp(&finding))
            .or_else(|| self.findings_read_watermark_for(&finding));
        vec![ShellEffect::RecordReviewDecision(ReviewDecisionApply {
            alias,
            decision,
            finding,
            read_watermark,
            target: self.target_owned(),
        })]
    }

    fn findings_read_watermark_for(&self, finding: &Finding) -> Option<u64> {
        let stable_fp = finding_stable_fp(finding);
        self.findings()
            .iter()
            .any(|row| finding_stable_fp(row) == stable_fp)
            .then(|| self.findings_read_watermark())
            .flatten()
    }

    fn parse_review_decision_verdict_or_log(
        &mut self,
        value: &str,
    ) -> Option<ReviewDecisionVerdict> {
        let verdict = parse_review_decision_verdict(value);
        if verdict.is_none() {
            self.log(
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
            self.log(
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
            self.log(
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
        self.log(
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
    ) {
        let message = error.to_string();
        if message.contains("changed after read watermark") {
            self.router.workbench_mut().review_mut().mode = ReviewMode::Conflict {
                message: message.clone(),
                target_fp: finding_stable_fp(finding).to_string(),
            };
        }
        self.log(
            "error",
            with_next_step(
                format!("could not save review decision: {message}"),
                "open a persisted finding, then retry decision <verdict> <reason>",
            ),
        );
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

pub(crate) fn finding_stable_fp(finding: &Finding) -> &str {
    finding
        .identity_id
        .as_deref()
        .unwrap_or(finding.fingerprint.as_str())
}

fn parse_review_decision_verdict(value: &str) -> Option<ReviewDecisionVerdict> {
    let normalized = value.trim().replace('-', "_");
    ReviewDecisionVerdict::from_str(&normalized)
}

pub(crate) fn review_decision_finding_label(alias: Option<&str>, finding: &Finding) -> String {
    alias
        .map(str::to_string)
        .unwrap_or_else(|| finding.fingerprint.chars().take(12).collect())
}
