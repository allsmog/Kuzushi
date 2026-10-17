use super::*;

impl<'a> LikelyVulnClassifier<'a> {
    pub fn new(runtime: &'a RoutedRuntime<'a>, cfg: ClassifierConfig) -> Result<Self> {
        cfg.validate()?;
        let quantile = match cfg.state_db.as_deref() {
            Some(db) => load_quantile(db, cfg.target_percentile)?,
            None => QuantileEstimator::new(cfg.target_percentile),
        };
        Ok(Self {
            runtime,
            cfg,
            quantile: Mutex::new(quantile),
        })
    }

    /// Assess a finding via the cheap classifier model.
    pub fn assess(&self, finding: &Finding, cwd: &Path) -> Result<ClassifierAssessment> {
        self.assess_with_cost(finding, cwd)
            .map(|(assessment, _)| assessment)
    }

    /// Compatibility wrapper for callers written against the score-only API.
    ///
    /// It reports the score for a readable response and an error for one the
    /// gate could not read — never the neutral `0.5` it used to manufacture,
    /// which fell below the default cold-start floor and rejected the finding
    /// it failed to read. Use [`Self::assess`], which makes that state
    /// representable instead of collapsing it into a number or an error.
    #[deprecated(
        since = "0.24.0",
        note = "use `assess`, which distinguishes a score from an unreadable response"
    )]
    pub fn score(&self, finding: &Finding, cwd: &Path) -> Result<Score> {
        self.assess(finding, cwd)?.score().ok_or_else(|| {
            anyhow::anyhow!("classifier gate response carried no usable verdict; call `assess`")
        })
    }

    pub(crate) fn assess_with_cost(
        &self,
        finding: &Finding,
        cwd: &Path,
    ) -> Result<(ClassifierAssessment, crate::runtime::RuntimeCostReport)> {
        let response = self.query_classifier(finding, cwd)?;
        let cost = response.checked_cost_report()?;
        let assessment = match parsed_classifier_score(&response) {
            Some(score) => {
                self.observe_score(score)?;
                ClassifierAssessment::Scored(score)
            }
            None => {
                record_parse_degraded();
                ClassifierAssessment::ParseDegraded
            }
        };
        Ok((assessment, cost))
    }

    fn query_classifier(&self, finding: &Finding, cwd: &Path) -> Result<AgentQueryResponse> {
        let model = self
            .runtime
            .resolve_model_for_role(AgentRole::ClassifierGate, 0, None)?;
        let request = AgentQueryRequest::new(
            model,
            cwd.to_path_buf(),
            CLASSIFIER_SYSTEM_PROMPT,
            bounded_classifier_prompt(finding)?,
        )
        .with_stage("finding-classifier")
        .with_tool_policy(crate::runtime::AgentToolPolicy::new(
            "finding-metadata-opinion",
            std::iter::empty::<&str>(),
        ))
        .with_max_model_turns(Some(1))
        .with_max_output_tokens(512);
        crate::runtime::query_blocking_checked(self.runtime, request)
            .context("classifier gate query failed")
    }

    fn observe_score(&self, score: Score) -> Result<()> {
        let mut quantile = self.quantile.lock().expect("quantile mutex poisoned");
        let mut next = quantile.clone();
        next.observe(score);
        if let Some(ref db) = self.cfg.state_db {
            save_quantile(db, &next).context("Could not retain classifier sample")?;
        }
        *quantile = next;
        Ok(())
    }

    /// Whether an assessment graduates to the deep auditor.
    ///
    /// A degraded assessment escalates. The gate exists to save the deep
    /// auditor's budget, and a gate that failed to read the model's answer has
    /// learned nothing that could stand in for a negative verdict.
    ///
    /// A bare [`Score`] still converts, so callers written against the
    /// score-only API keep compiling and keep their threshold semantics.
    pub fn should_deep_audit(&self, assessment: impl Into<ClassifierAssessment>) -> bool {
        match assessment.into() {
            ClassifierAssessment::Scored(score) => score >= self.current_threshold(),
            ClassifierAssessment::ParseDegraded => true,
        }
    }

    #[cfg(test)]
    pub(crate) fn observed_score_count_for_test(&self) -> usize {
        self.quantile.lock().expect("quantile mutex poisoned").count
    }

    /// Build a [`TriageOutcome`] for a finding the gate has rejected.
    /// Used when the score is below the threshold and we don't want to
    /// spend the deep auditor's budget.
    pub fn skip_outcome(&self, score: Score) -> TriageOutcome {
        self.skip_outcome_with_cost(
            score,
            crate::runtime::RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO),
        )
    }

    pub(crate) fn skip_outcome_with_cost(
        &self,
        score: Score,
        cost: crate::runtime::RuntimeCostReport,
    ) -> TriageOutcome {
        TriageOutcome {
            verdict: TriageVerdict::NeedsReview,
            confidence: score.clamp(0.0, 1.0),
            rationale: format!(
                "below adaptive triage threshold (score={:.2}, threshold={:.2}, n={})",
                score,
                self.current_threshold(),
                self.quantile.lock().unwrap().count
            ),
            refute_reason: None,
            first_link: None,
            cost_usd: cost.observed_usd(),
            cost_usd_exact: cost.is_complete(),
            estimated_cost_usd: cost.unmetered_estimate_usd(),
        }
    }

    pub fn current_threshold(&self) -> f32 {
        let q = self.quantile.lock().expect("quantile mutex poisoned");
        if q.count < self.cfg.cold_start_min_count {
            self.cfg.cold_start_floor
        } else {
            q.estimate()
        }
    }

    pub fn samples_seen(&self) -> usize {
        self.quantile.lock().unwrap().count
    }
}

fn parsed_classifier_score(response: &AgentQueryResponse) -> Option<Score> {
    let parsed = match &response.structured {
        Some(value) => serde_json::from_value::<ClassifierResponse>(value.clone()).ok()?,
        None => try_loose_parse(&response.text)?,
    };
    (parsed.score.is_finite() && (0.0..=1.0).contains(&parsed.score)).then_some(parsed.score)
}

fn record_parse_degraded() {
    crate::runtime_diagnostics::record_runtime_diagnostic(
        "classifier",
        "classifier response carried no usable score; preserving review eligibility \
         without a score, quantile sample or follow-up request",
    );
}
