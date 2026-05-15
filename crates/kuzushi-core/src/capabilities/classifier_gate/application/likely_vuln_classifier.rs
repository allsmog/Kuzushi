use super::*;

impl<'a> LikelyVulnClassifier<'a> {
    pub fn new(runtime: &'a RoutedRuntime, cfg: ClassifierConfig) -> Result<Self> {
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
        let model = self
            .runtime
            .resolve_model_for_role(AgentRole::ClassifierGate, 0, None)?;
        let request = AgentQueryRequest::new(
            model,
            cwd.to_path_buf(),
            CLASSIFIER_SYSTEM_PROMPT,
            render_prompt(finding),
        );
        let response = self
            .runtime
            .query_blocking(request)
            .context("classifier gate query failed")?;

        // Parse score from structured field, or extract from text.
        let parsed = response
            .structured
            .as_ref()
            .and_then(|v| serde_json::from_value::<ClassifierResponse>(v.clone()).ok())
            .or_else(|| try_loose_parse(&response.text));
        let raw = parsed
            .map(|p| {
                let s = if p.score > 0.0 {
                    p.score
                } else if p.likely {
                    0.85
                } else {
                    0.15
                };
                s.clamp(0.0, 1.0)
            })
            .unwrap_or_else(|| {
                // Conservative fallback: if we can't parse, score in the
                // middle so the gate doesn't reject a real bug just because
                // the model burped.
                0.5
            });

        // Update quantile and persist if configured.
        let mut q = self.quantile.lock().expect("quantile mutex poisoned");
        q.observe(raw);
        if let Some(ref db) = self.cfg.state_db {
            // Best-effort: a persistence failure must not block the scan.
            let _ = save_quantile(db, &q);
        }
        Ok(raw)
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

    /// Build a [`TriageOutcome`] for a finding the gate has rejected.
    /// Used when the score is below the threshold and we don't want to
    /// spend the deep auditor's budget.
    pub fn skip_outcome(&self, score: Score) -> TriageOutcome {
        TriageOutcome {
            verdict: TriageVerdict::NeedsReview,
            confidence: score.clamp(0.0, 1.0),
            rationale: format!(
                "below adaptive triage threshold (score={:.2}, threshold={:.2}, n={})",
                score,
                self.current_threshold(),
                self.quantile.lock().unwrap().count
            ),
            cost_usd: 0.0,
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
