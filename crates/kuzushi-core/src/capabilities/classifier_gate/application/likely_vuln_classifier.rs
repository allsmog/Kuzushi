use super::*;

impl<'a> LikelyVulnClassifier<'a> {
    pub fn new(runtime: &'a RoutedRuntime<'a>, cfg: ClassifierConfig) -> Result<Self> {
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

    /// Score a finding via the cheap classifier model.
    pub fn score(&self, finding: &Finding, cwd: &Path) -> Result<Score> {
        self.score_with_cost(finding, cwd).map(|(score, _)| score)
    }

    pub(crate) fn score_with_cost(
        &self,
        finding: &Finding,
        cwd: &Path,
    ) -> Result<(Score, crate::runtime::RuntimeCostReport)> {
        let response = self.query_classifier(finding, cwd)?;
        let cost = response.checked_cost_report()?;
        let parsed_score = parsed_classifier_score(&response);
        let parsed_response = parsed_score.is_some();
        let raw = parsed_score.unwrap_or_else(neutral_classifier_score);
        self.observe_parsed_score(parsed_response, raw);
        Ok((raw, cost))
    }

    fn query_classifier(&self, finding: &Finding, cwd: &Path) -> Result<AgentQueryResponse> {
        let model = self
            .runtime
            .resolve_model_for_role(AgentRole::ClassifierGate, 0, None)?;
        let request = AgentQueryRequest::new(
            model,
            cwd.to_path_buf(),
            CLASSIFIER_SYSTEM_PROMPT,
            render_prompt(finding),
        );
        crate::runtime::query_blocking_checked(self.runtime, request)
            .context("classifier gate query failed")
    }

    fn observe_parsed_score(&self, parsed_response: bool, raw: Score) {
        if !parsed_response {
            return;
        }
        let mut quantile = self.quantile.lock().expect("quantile mutex poisoned");
        quantile.observe(raw);
        if let Some(ref db) = self.cfg.state_db {
            // Best-effort: a persistence failure must not block the scan.
            let _ = save_quantile(db, &quantile);
        }
    }

    /// Whether a score graduates to the deep auditor.
    pub fn should_deep_audit(&self, score: Score) -> bool {
        let q = self.quantile.lock().expect("quantile mutex poisoned");
        if q.count < self.cfg.cold_start_min_count {
            score >= self.cfg.cold_start_floor
        } else {
            score >= q.estimate()
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
            cost_usd: cost.observed_usd(),
            cost_usd_exact: cost.is_complete(),
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
    let parsed = response
        .structured
        .as_ref()
        .and_then(|v| serde_json::from_value::<ClassifierResponse>(v.clone()).ok())
        .or_else(|| try_loose_parse(&response.text))?;
    Some(classifier_response_score(parsed))
}

fn classifier_response_score(response: ClassifierResponse) -> Score {
    let score = if response.score > 0.0 {
        response.score
    } else if response.likely {
        0.85
    } else {
        0.15
    };
    score.clamp(0.0, 1.0)
}

fn neutral_classifier_score() -> Score {
    crate::runtime_diagnostics::record_runtime_diagnostic(
        "classifier",
        "classifier gate response was unparseable; using neutral score without training quantile",
    );
    // Conservative fallback: if we can't parse, score in the middle so the
    // gate doesn't reject a real bug just because the model burped.
    0.5
}
