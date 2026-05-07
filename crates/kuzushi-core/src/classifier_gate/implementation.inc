use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::agent_router::{AgentRole, RoutedRuntime};
use crate::findings::{Finding, TriageOutcome, TriageVerdict};
use crate::runtime::{AgentQueryRequest, AgentRuntime};

pub const DEFAULT_TARGET_PERCENTILE: f32 = 0.80;
pub const DEFAULT_COLD_START_FLOOR: f32 = 0.6;
pub const DEFAULT_COLD_START_MIN_COUNT: usize = 50;

const STATE_KEY: &str = "classifier.likely_vuln.quantile";

/// P²-algorithm streaming quantile estimator. Maintains five marker
/// heights/positions and updates them as new samples arrive — O(1)
/// memory and O(1) update cost, no full sort needed.
///
/// Reference: Jain & Chlamtac, "The P² Algorithm for Dynamic
/// Calculation of Quantiles and Histograms Without Storing
/// Observations", CACM 28(10), 1985.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantileEstimator {
    /// Target percentile, e.g. 0.80.
    pub p: f32,
    /// Heights of the five markers q[0..5].
    q: [f64; 5],
    /// Actual positions n[0..5] (1-indexed).
    n: [f64; 5],
    /// Desired positions np[0..5].
    np: [f64; 5],
    /// Increments dn[0..5].
    dn: [f64; 5],
    /// Number of samples seen.
    pub count: usize,
}

impl QuantileEstimator {
    pub fn new(p: f32) -> Self {
        let p = p.clamp(0.0, 1.0) as f64;
        Self {
            p: p as f32,
            q: [0.0; 5],
            n: [1.0, 2.0, 3.0, 4.0, 5.0],
            np: [1.0, 1.0 + 2.0 * p, 1.0 + 4.0 * p, 3.0 + 2.0 * p, 5.0],
            dn: [0.0, p / 2.0, p, (1.0 + p) / 2.0, 1.0],
            count: 0,
        }
    }

    /// Add a sample. Returns the current estimate.
    pub fn observe(&mut self, x: f32) -> f32 {
        let x = x as f64;
        self.count += 1;

        // Initial fill: store the first 5 samples sorted.
        if self.count <= 5 {
            self.q[self.count - 1] = x;
            if self.count == 5 {
                self.q
                    .sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            }
            return self.estimate();
        }

        // Find the cell `k` such that q[k] <= x < q[k+1].
        let k = if x < self.q[0] {
            self.q[0] = x;
            0
        } else if x < self.q[1] {
            0
        } else if x < self.q[2] {
            1
        } else if x < self.q[3] {
            2
        } else if x < self.q[4] {
            3
        } else {
            self.q[4] = x;
            3
        };

        // Increment positions.
        for i in (k + 1)..5 {
            self.n[i] += 1.0;
        }
        for i in 0..5 {
            self.np[i] += self.dn[i];
        }

        // Adjust marker heights.
        for i in 1..4 {
            let d = self.np[i] - self.n[i];
            if (d >= 1.0 && self.n[i + 1] - self.n[i] > 1.0)
                || (d <= -1.0 && self.n[i - 1] - self.n[i] < -1.0)
            {
                let d_sign = d.signum();
                let qp = self.parabolic(i, d_sign);
                if self.q[i - 1] < qp && qp < self.q[i + 1] {
                    self.q[i] = qp;
                } else {
                    self.q[i] = self.linear(i, d_sign);
                }
                self.n[i] += d_sign;
            }
        }

        self.estimate()
    }

    fn parabolic(&self, i: usize, d: f64) -> f64 {
        let n = self.n;
        let q = self.q;
        q[i] + d / (n[i + 1] - n[i - 1])
            * ((n[i] - n[i - 1] + d) * (q[i + 1] - q[i]) / (n[i + 1] - n[i])
                + (n[i + 1] - n[i] - d) * (q[i] - q[i - 1]) / (n[i] - n[i - 1]))
    }

    fn linear(&self, i: usize, d: f64) -> f64 {
        let next = if d > 0.0 { i + 1 } else { i - 1 };
        self.q[i] + d * (self.q[next] - self.q[i]) / (self.n[next] - self.n[i])
    }

    /// Current estimate of the p-th quantile.
    pub fn estimate(&self) -> f32 {
        if self.count == 0 {
            return 0.0;
        }
        if self.count <= 5 {
            // For partial fills, sort the populated prefix and return the
            // closest stored value to the target percentile.
            let mut sorted: Vec<f64> = self.q[..self.count].to_vec();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let idx = ((self.p as f64) * (self.count as f64 - 1.0)).round() as usize;
            return sorted[idx.min(self.count - 1)] as f32;
        }
        self.q[2] as f32
    }
}

/// Score returned by the classifier — `[0.0, 1.0]` where 1.0 means
/// "almost certainly a real vulnerability".
pub type Score = f32;

#[derive(Debug, Clone)]
pub struct ClassifierConfig {
    pub target_percentile: f32,
    pub cold_start_floor: f32,
    pub cold_start_min_count: usize,
    /// Path to the SQLite DB used to persist the quantile across
    /// invocations. `None` = in-memory only (tests / dry runs).
    pub state_db: Option<std::path::PathBuf>,
}

impl Default for ClassifierConfig {
    fn default() -> Self {
        Self {
            target_percentile: DEFAULT_TARGET_PERCENTILE,
            cold_start_floor: DEFAULT_COLD_START_FLOOR,
            cold_start_min_count: DEFAULT_COLD_START_MIN_COUNT,
            state_db: None,
        }
    }
}

const CLASSIFIER_SYSTEM_PROMPT: &str = r#"You are Kuzushi's classifier gate. You see one
candidate finding from a SAST tool and decide whether it is plausibly a real, triggerable
vulnerability that an attacker can exploit with realistic input.

Return ONLY a JSON object matching:

{ "likely": bool, "score": 0.0..=1.0, "reason": "one sentence" }

Be calibrated, not generous. A score of 0.8 means you are 80% confident a deep auditor
would mark this true_positive. A score of 0.2 means you would expect false_positive.
Reserve scores above 0.9 for cases with obvious user-controlled input flowing into a
clear sink with no visible guard."#;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ClassifierResponse {
    #[serde(default)]
    likely: bool,
    #[serde(default)]
    score: f32,
    /// The model's stated reason. Surfaced via the rationale on
    /// `skip_outcome` only — kept for forward-compat / log enrichment.
    #[serde(default)]
    reason: String,
}

pub struct LikelyVulnClassifier<'a> {
    runtime: &'a RoutedRuntime,
    cfg: ClassifierConfig,
    quantile: Mutex<QuantileEstimator>,
}

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
            .resolve_model(AgentRole::ClassifierGate, 0, None)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no model configured for classifier_gate role: \
                     set models.toml [roles.classifier_gate] or `setg MODEL_CLASSIFIER_GATE`"
                )
            })?;
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

fn render_prompt(f: &Finding) -> String {
    format!(
        "tool       : {tool}\n\
         rule_id    : {rule}\n\
         severity   : {sev}\n\
         file       : {file}:{line}\n\
         title      : {title}\n\
         message    :\n{msg}",
        tool = f.tool,
        rule = f.rule_id,
        sev = f.severity.as_str(),
        file = f.file_path,
        line = f.start_line,
        title = f.title,
        msg = f.message,
    )
}

fn try_loose_parse(text: &str) -> Option<ClassifierResponse> {
    let trimmed = text.trim();
    let stripped = if trimmed.starts_with("```") {
        trimmed
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim()
            .to_string()
    } else {
        trimmed.to_string()
    };
    if let Ok(v) = serde_json::from_str(&stripped) {
        return Some(v);
    }
    let start = stripped.find('{')?;
    let end = stripped.rfind('}')?;
    serde_json::from_str(&stripped[start..=end]).ok()
}

fn load_quantile(db: &Path, target_p: f32) -> Result<QuantileEstimator> {
    let conn = open_state_conn(db)?;
    let raw: Option<Vec<u8>> = conn
        .query_row(
            "select value from kuzushi_state where key = ?",
            params![STATE_KEY],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(bytes) = raw {
        if let Ok(state) = serde_json::from_slice::<QuantileEstimator>(&bytes) {
            return Ok(state);
        }
    }
    Ok(QuantileEstimator::new(target_p))
}

fn save_quantile(db: &Path, q: &QuantileEstimator) -> Result<()> {
    let conn = open_state_conn(db)?;
    let body = serde_json::to_vec(q).context("serialise quantile state")?;
    conn.execute(
        "insert into kuzushi_state(key, value, updated_at)
         values (?, ?, ?)
         on conflict(key) do update set value = excluded.value, updated_at = excluded.updated_at",
        params![STATE_KEY, body, current_unix_seconds()],
    )?;
    Ok(())
}

fn open_state_conn(db: &Path) -> Result<Connection> {
    let conn = Connection::open(db)?;
    // The kuzushi_state table is created by the spend ledger schema; if
    // a caller uses the classifier without spend, ensure it exists.
    conn.execute_batch(
        r#"
        create table if not exists kuzushi_state (
          key        text    primary key,
          value      blob,
          updated_at integer not null
        );
        "#,
    )?;
    Ok(conn)
}

fn current_unix_seconds() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_router::{AgentRouter, RoutedRuntime};
    use crate::config::ConfigPaths;
    use crate::findings::Severity;
    use crate::runtime::{AgentQueryResponse, TriageRequest};
    use std::sync::Arc;

    /// Mock runtime that returns a canned classifier score for every query.
    struct CannedRuntime {
        score: f32,
        likely: bool,
    }
    impl AgentRuntime for CannedRuntime {
        fn query_blocking(&self, _req: AgentQueryRequest) -> Result<AgentQueryResponse> {
            Ok(AgentQueryResponse {
                text: String::new(),
                structured: Some(serde_json::json!({
                    "likely": self.likely,
                    "score": self.score,
                    "reason": "test"
                })),
                ..Default::default()
            })
        }
        fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
            unreachable!()
        }
    }

    fn synth_finding(rule: &str) -> Finding {
        Finding::new_tool(
            "semgrep",
            rule,
            "src/foo.c",
            10,
            Some(15),
            Severity::Medium,
            "candidate",
        )
    }

    fn router_with_classifier_role(model: &str) -> AgentRouter {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".kuzushi");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("models.toml"),
            format!("[roles.classifier_gate]\nprimary = \"{model}\"\n"),
        )
        .unwrap();
        let r = AgentRouter::load(&ConfigPaths {
            home_dir: tmp.path().to_path_buf(),
            target_dir: None,
        })
        .unwrap();
        let _ = tmp;
        r
    }

    fn routed(score: f32, likely: bool) -> RoutedRuntime {
        let inner: Arc<dyn AgentRuntime> = Arc::new(CannedRuntime { score, likely });
        RoutedRuntime::new(
            inner,
            Arc::new(router_with_classifier_role("anthropic:claude-haiku-4-5")),
            None,
        )
    }

    #[test]
    fn quantile_estimator_p80_converges_to_correct_value() {
        let mut q = QuantileEstimator::new(0.80);
        // Uniform 0..1 stream — 80th percentile should approach 0.8.
        for i in 0..1000 {
            q.observe((i as f32) / 999.0);
        }
        let est = q.estimate();
        assert!((est - 0.8).abs() < 0.05, "expected ~0.8, got {est}");
    }

    #[test]
    fn cold_start_uses_floor_until_min_samples() {
        let runtime = routed(0.7, true);
        let cfg = ClassifierConfig {
            cold_start_min_count: 5,
            cold_start_floor: 0.5,
            ..Default::default()
        };
        let gate = LikelyVulnClassifier::new(&runtime, cfg).unwrap();
        // Score 4 findings — still in cold-start.
        for i in 0..4 {
            let f = synth_finding(&format!("rule-{i}"));
            let _ = gate.score(&f, Path::new(".")).unwrap();
        }
        assert_eq!(gate.samples_seen(), 4);
        // 0.7 ≥ 0.5 → graduates.
        assert!(gate.should_deep_audit(0.7));
        // 0.4 < 0.5 → rejected.
        assert!(!gate.should_deep_audit(0.4));
        // Threshold should still be the floor.
        assert!((gate.current_threshold() - 0.5).abs() < 1e-6);
    }

    #[test]
    fn quantile_state_persists_across_reload() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("findings.sqlite3");
        // First gate observes 60 samples at increasing scores.
        {
            let runtime = routed(0.5, true);
            let cfg = ClassifierConfig {
                cold_start_min_count: 10,
                state_db: Some(db.clone()),
                ..Default::default()
            };
            let gate = LikelyVulnClassifier::new(&runtime, cfg).unwrap();
            for i in 0..60 {
                let f = synth_finding(&format!("rule-{i}"));
                let _ = gate.score(&f, Path::new(".")).unwrap();
            }
            assert_eq!(gate.samples_seen(), 60);
        }
        // Second gate, reopened on the same DB, must see the persisted
        // 60-sample state.
        let runtime = routed(0.5, true);
        let cfg = ClassifierConfig {
            cold_start_min_count: 10,
            state_db: Some(db.clone()),
            ..Default::default()
        };
        let gate = LikelyVulnClassifier::new(&runtime, cfg).unwrap();
        assert_eq!(gate.samples_seen(), 60);
    }

    #[test]
    fn skip_outcome_records_threshold_in_rationale() {
        let runtime = routed(0.7, true);
        let gate = LikelyVulnClassifier::new(&runtime, ClassifierConfig::default()).unwrap();
        let outcome = gate.skip_outcome(0.3);
        assert_eq!(outcome.verdict, TriageVerdict::NeedsReview);
        assert!(outcome.rationale.contains("score=0.30"));
        assert!(outcome.rationale.contains("threshold="));
    }

    #[test]
    fn likely_true_no_score_falls_back_to_0_85() {
        // Mock that returns likely:true with score:0 — classifier must
        // not interpret 0 as "definitely false"; should fall back to a
        // sensible default for likely=true.
        struct Q;
        impl AgentRuntime for Q {
            fn query_blocking(&self, _: AgentQueryRequest) -> Result<AgentQueryResponse> {
                Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(serde_json::json!({
                        "likely": true, "score": 0.0, "reason": "no score"
                    })),
                    ..Default::default()
                })
            }
            fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
                unreachable!()
            }
        }
        let inner: Arc<dyn AgentRuntime> = Arc::new(Q);
        let runtime = RoutedRuntime::new(
            inner,
            Arc::new(router_with_classifier_role("anthropic:claude-haiku-4-5")),
            None,
        );
        let gate = LikelyVulnClassifier::new(&runtime, ClassifierConfig::default()).unwrap();
        let s = gate.score(&synth_finding("r"), Path::new(".")).unwrap();
        assert!((s - 0.85).abs() < 1e-6, "got {s}");
    }

    #[test]
    fn unparseable_response_falls_back_to_neutral_score() {
        struct Q;
        impl AgentRuntime for Q {
            fn query_blocking(&self, _: AgentQueryRequest) -> Result<AgentQueryResponse> {
                Ok(AgentQueryResponse {
                    text: "I don't know what to say".to_string(),
                    structured: None,
                    ..Default::default()
                })
            }
            fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
                unreachable!()
            }
        }
        let inner: Arc<dyn AgentRuntime> = Arc::new(Q);
        let runtime = RoutedRuntime::new(
            inner,
            Arc::new(router_with_classifier_role("anthropic:claude-haiku-4-5")),
            None,
        );
        let gate = LikelyVulnClassifier::new(&runtime, ClassifierConfig::default()).unwrap();
        let s = gate.score(&synth_finding("r"), Path::new(".")).unwrap();
        // Neutral fallback so a junk response doesn't auto-reject a real bug.
        assert!((s - 0.5).abs() < 1e-6, "got {s}");
    }

    #[test]
    fn loose_json_in_text_is_parsed() {
        struct Q;
        impl AgentRuntime for Q {
            fn query_blocking(&self, _: AgentQueryRequest) -> Result<AgentQueryResponse> {
                Ok(AgentQueryResponse {
                    text: "Sure: ```json\n{\"likely\":true,\"score\":0.92,\"reason\":\"obvious\"}\n```"
                        .to_string(),
                    structured: None,
                    ..Default::default()
                })
            }
            fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
                unreachable!()
            }
        }
        let inner: Arc<dyn AgentRuntime> = Arc::new(Q);
        let runtime = RoutedRuntime::new(
            inner,
            Arc::new(router_with_classifier_role("anthropic:claude-haiku-4-5")),
            None,
        );
        let gate = LikelyVulnClassifier::new(&runtime, ClassifierConfig::default()).unwrap();
        let s = gate.score(&synth_finding("r"), Path::new(".")).unwrap();
        assert!((s - 0.92).abs() < 1e-6, "got {s}");
    }
}
