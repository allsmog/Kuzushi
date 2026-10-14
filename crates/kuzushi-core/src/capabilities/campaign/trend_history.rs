//! Workspace trend history: an append-only JSONL of trend snapshots at
//! `.kuzushi/trend-history.jsonl`, plus the sparkline fold rendered beside
//! the TREND strip. Same one-pure-fold discipline as `trend.rs`: this is
//! the single history implementation consumed by `campaign:status`, the
//! campaign deck, and the Report header, so all three tell the same story.

use super::trend::TrendMetrics;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Write;
use std::path::{Path, PathBuf};

mod recent;

/// Snapshots surfaced to consumers (JSON + sparkline). The file may hold
/// more; readers see the most recent window.
pub const TREND_HISTORY_LIMIT: usize = 90;

const SPARK_GLYPHS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrendSnapshot {
    pub ts_ms: u64,
    pub decided_findings: usize,
    pub confirmed_findings: usize,
    pub rejected_false_positives: usize,
    pub campaign_spend_usd: f64,
    #[serde(default)]
    pub provider_spend_unresolved: bool,
}

impl TrendSnapshot {
    pub fn fp_rate(&self) -> Option<f64> {
        (self.decided_findings > 0)
            .then(|| self.rejected_false_positives as f64 / self.decided_findings as f64)
    }

    /// Snapshot equality for dedupe — everything but the timestamp.
    fn same_state(&self, other: &TrendSnapshot) -> bool {
        self.decided_findings == other.decided_findings
            && self.confirmed_findings == other.confirmed_findings
            && self.rejected_false_positives == other.rejected_false_positives
            && self.campaign_spend_usd == other.campaign_spend_usd
            && self.provider_spend_unresolved == other.provider_spend_unresolved
    }
}

pub fn trend_history_path(root: &Path) -> PathBuf {
    crate::workspace::workspace_state_root(root).join("trend-history.jsonl")
}

/// Append the current trend as a snapshot line unless it is identical to
/// the last recorded one (a status poll loop must not grow the file).
/// Returns whether a line was appended.
///
/// Metrics whose decision ledger could not be read are never recorded: the
/// zeros they carry stand for an unread database, and a history line cannot
/// say that. Persisting them would turn one failed read into a permanent
/// dip in every sparkline drawn afterwards.
pub fn record_trend_snapshot(root: &Path, metrics: &TrendMetrics) -> Result<bool> {
    if metrics.decisions_unreadable {
        return Ok(false);
    }
    let snapshot = TrendSnapshot {
        ts_ms: now_ms(),
        decided_findings: metrics.decided_findings,
        confirmed_findings: metrics.confirmed_findings,
        rejected_false_positives: metrics.rejected_false_positives,
        campaign_spend_usd: metrics.campaign_spend_usd,
        provider_spend_unresolved: metrics.provider_spend_unresolved,
    };
    let path = trend_history_path(root);
    if last_snapshot(root, &path).is_some_and(|last| last.same_state(&snapshot)) {
        return Ok(false);
    }
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("Could not create {}", parent.display()))?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("Could not open {}", path.display()))?;
    let line = serde_json::to_string(&snapshot).context("Could not serialize trend snapshot")?;
    writeln!(file, "{line}").with_context(|| format!("Could not append {}", path.display()))?;
    Ok(true)
}

fn last_snapshot(root: &Path, path: &Path) -> Option<TrendSnapshot> {
    recent::load_recent_history(root, path, 1).ok()?.pop()
}

/// Most recent valid snapshots, oldest first, up to `limit` or 90 rows.
/// Reads at most the last 1 MiB; partial and malformed lines are skipped.
pub fn load_trend_history(root: &Path, limit: usize) -> Vec<TrendSnapshot> {
    recent::load_recent_history(root, &trend_history_path(root), limit).unwrap_or_default()
}

pub(super) fn history_window_json() -> Value {
    serde_json::json!({
        "selection": "recent-valid-lines",
        "maxSnapshots": TREND_HISTORY_LIMIT,
        "maxReadBytes": recent::MAX_HISTORY_BYTES,
    })
}

pub fn history_json(history: &[TrendSnapshot]) -> Value {
    serde_json::json!(history
        .iter()
        .map(|snapshot| {
            serde_json::json!({
                "tsMs": snapshot.ts_ms,
                "decidedFindings": snapshot.decided_findings,
                "confirmedFindings": snapshot.confirmed_findings,
                "rejectedFalsePositives": snapshot.rejected_false_positives,
                "campaignSpendUsd": snapshot.campaign_spend_usd,
                "providerSpendUnresolved": snapshot.provider_spend_unresolved,
                "fpRate": snapshot.fp_rate(),
            })
        })
        .collect::<Vec<_>>())
}

/// Unicode sparkline over raw values, min-max normalized to eight glyph
/// levels. Fewer than two points yields an empty string — a single dot is
/// not a trend and must not render as one.
pub fn sparkline(values: &[f64]) -> String {
    if values.len() < 2 {
        return String::new();
    }
    let (min, max) = values
        .iter()
        .fold((f64::MAX, f64::MIN), |(lo, hi), v| (lo.min(*v), hi.max(*v)));
    let span = max - min;
    values
        .iter()
        .map(|value| {
            let level = if span <= f64::EPSILON {
                (SPARK_GLYPHS.len() - 1) / 2
            } else {
                (((value - min) / span) * (SPARK_GLYPHS.len() - 1) as f64).round() as usize
            };
            SPARK_GLYPHS[level.min(SPARK_GLYPHS.len() - 1)]
        })
        .collect()
}

/// Compact recent history label; fewer than two snapshots has no trend.
pub fn history_strip_label(history: &[TrendSnapshot]) -> Option<String> {
    history_reading_lines(history).map(|lines| lines.join(" · "))
}

/// Separate count and chart labels so a narrow reader can retain qualifiers.
pub fn history_reading_lines(history: &[TrendSnapshot]) -> Option<[String; 3]> {
    if history.len() < 2 {
        return None;
    }
    let spend: Vec<f64> = history
        .iter()
        .map(|snapshot| snapshot.campaign_spend_usd)
        .collect();
    let spend_label = if history
        .iter()
        .any(|snapshot| snapshot.provider_spend_unresolved)
    {
        "spend >="
    } else {
        "spend"
    };
    Some([
        format!("HISTORY recent · {} snapshot(s)", history.len()),
        format!("fp {}", history_false_positive_plot(history)),
        format!("{spend_label} {}", sparkline(&spend)),
    ])
}

fn history_false_positive_plot(history: &[TrendSnapshot]) -> String {
    let rates = history
        .iter()
        .map(TrendSnapshot::fp_rate)
        .collect::<Option<Vec<_>>>();
    rates
        .map(|values| sparkline(&values))
        .unwrap_or_else(|| "unavailable (snapshots without decisions)".into())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics(decided: usize, rejected: usize, confirmed: usize, spend: f64) -> TrendMetrics {
        TrendMetrics {
            decided_findings: decided,
            rejected_false_positives: rejected,
            confirmed_findings: confirmed,
            campaign_spend_usd: spend,
            provider_spend_unresolved: false,
            decisions_unreadable: false,
        }
    }

    #[test]
    fn an_unreadable_ledger_is_refused_so_it_cannot_dip_the_sparkline() {
        let tmp = tempfile::tempdir().unwrap();
        let unreadable = TrendMetrics {
            decisions_unreadable: true,
            ..metrics(0, 0, 0, 10.0)
        };

        assert!(!record_trend_snapshot(tmp.path(), &unreadable).unwrap());
        assert!(!trend_history_path(tmp.path()).exists());
        // A workspace that genuinely has no decisions yet still records.
        assert!(record_trend_snapshot(tmp.path(), &metrics(0, 0, 0, 10.0)).unwrap());
        assert_eq!(load_trend_history(tmp.path(), TREND_HISTORY_LIMIT).len(), 1);
    }

    #[test]
    fn record_appends_on_change_and_dedupes_identical_consecutive_snapshots() {
        let tmp = tempfile::tempdir().unwrap();

        assert!(record_trend_snapshot(tmp.path(), &metrics(3, 1, 2, 10.0)).unwrap());
        // Same state polled again — no new line.
        assert!(!record_trend_snapshot(tmp.path(), &metrics(3, 1, 2, 10.0)).unwrap());
        // Spend moved — appended.
        assert!(record_trend_snapshot(tmp.path(), &metrics(3, 1, 2, 12.5)).unwrap());
        // A decision landed — appended.
        assert!(record_trend_snapshot(tmp.path(), &metrics(4, 1, 3, 12.5)).unwrap());

        let history = load_trend_history(tmp.path(), TREND_HISTORY_LIMIT);
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].campaign_spend_usd, 10.0);
        assert_eq!(history[2].confirmed_findings, 3);
    }

    #[test]
    fn load_bounds_to_most_recent_window_and_skips_torn_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let path = trend_history_path(tmp.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut body = String::new();
        for index in 0..(TREND_HISTORY_LIMIT + 10) {
            body.push_str(&format!(
                "{{\"tsMs\":{index},\"decidedFindings\":{index},\"confirmedFindings\":0,\"rejectedFalsePositives\":0,\"campaignSpendUsd\":0.0}}\n"
            ));
        }
        body.push_str("{\"tsMs\":999,\"decid"); // torn tail
        std::fs::write(&path, body).unwrap();

        let history = load_trend_history(tmp.path(), TREND_HISTORY_LIMIT);

        assert_eq!(history.len(), TREND_HISTORY_LIMIT);
        assert_eq!(history[0].decided_findings, 10);
        assert_eq!(
            history.last().unwrap().decided_findings,
            TREND_HISTORY_LIMIT + 9
        );
    }

    #[test]
    fn sparkline_maps_monotonic_series_to_rising_glyphs_and_flat_to_midline() {
        assert_eq!(sparkline(&[0.0, 1.0, 2.0, 3.0]), "▁▃▆█");
        assert_eq!(sparkline(&[5.0, 5.0, 5.0]), "▄▄▄");
        assert_eq!(sparkline(&[1.0]), "");
        assert_eq!(sparkline(&[]), "");
    }

    #[test]
    fn history_strip_is_honest_below_two_points() {
        let one = vec![TrendSnapshot {
            ts_ms: 1,
            decided_findings: 2,
            confirmed_findings: 1,
            rejected_false_positives: 1,
            campaign_spend_usd: 3.0,
            provider_spend_unresolved: false,
        }];
        assert_eq!(history_strip_label(&[]), None);
        assert_eq!(history_strip_label(&one), None);

        let mut two = one.clone();
        two.push(TrendSnapshot {
            ts_ms: 2,
            decided_findings: 4,
            confirmed_findings: 3,
            rejected_false_positives: 1,
            campaign_spend_usd: 9.0,
            provider_spend_unresolved: false,
        });
        let label = history_strip_label(&two).unwrap();
        assert_eq!(label, "HISTORY recent · 2 snapshot(s) · fp █▁ · spend ▁█");
    }

    #[test]
    fn missing_decisions_do_not_become_a_zero_false_positive_trend() {
        let history = vec![
            TrendSnapshot {
                ts_ms: 1,
                decided_findings: 0,
                confirmed_findings: 0,
                rejected_false_positives: 0,
                campaign_spend_usd: 0.0,
                provider_spend_unresolved: true,
            };
            2
        ];
        let label = history_strip_label(&history).unwrap();
        assert!(label.contains("fp unavailable (snapshots without decisions)"));
        assert!(label.contains("spend >="));
    }
}
