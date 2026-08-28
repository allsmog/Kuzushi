//! Detect completed direct (non-campaign) scan runs whose scope overlaps a
//! freshly planned job. The coverage fold reads only campaign queue state,
//! so a scan launched straight from the TUI/shell never marks a cell and
//! `fillGaps` re-plans — and re-pays for — work a completed run already did.
//! The planner WARNS about the overlap; it never auto-skips, because a
//! deliberate re-scan is legitimate.

use serde_json::Value;
use std::path::{Path, PathBuf};

pub(super) struct PriorScanOverlap {
    pub(super) shard: String,
    pub(super) run_id: String,
    pub(super) completed_at_unix: Option<u64>,
}

/// Run-history walk stays bounded on estates with years of runs: entries are
/// name-sorted descending (run ids embed a millisecond timestamp, so this is
/// newest-first) and capped.
const MAX_RUN_DIRS: usize = 4096;
const MAX_RUN_JSON_BYTES: usize = 262_144;
/// input.json can carry a full seasoned prompt alongside the scope options.
const MAX_INPUT_JSON_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn prior_scan_overlaps(
    root: &Path,
    tool: &str,
    shards: &[(String, Vec<String>)],
) -> Vec<PriorScanOverlap> {
    let mut overlaps: Vec<PriorScanOverlap> = Vec::new();
    for run_dir in run_dirs(root) {
        let Some((run_id, completed_at)) = completed_direct_run(&run_dir, tool) else {
            continue;
        };
        let Some(scope) = run_scope(&run_dir) else {
            continue;
        };
        for (shard, paths) in shards {
            if scope_matches_shard(&scope, shard, paths) {
                record_latest(&mut overlaps, shard, &run_id, completed_at);
            }
        }
    }
    overlaps
}

fn run_dirs(root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(root.join(".kuzushi/v3/runs")) else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort_by(|left, right| right.file_name().cmp(&left.file_name()));
    dirs.truncate(MAX_RUN_DIRS);
    dirs
}

/// Campaign-dispatched jobs record `kind: "run"` and already flow into the
/// coverage fold via queue state; only `kind: "tool"` (direct) runs are the
/// blind spot this module exists for.
fn completed_direct_run(run_dir: &Path, tool: &str) -> Option<(String, Option<u64>)> {
    let body =
        crate::bounded_file::read_utf8_text(&run_dir.join("run.json"), MAX_RUN_JSON_BYTES).ok()?;
    let run: Value = serde_json::from_str(&body).ok()?;
    let matches = run.get("kind").and_then(Value::as_str) == Some("tool")
        && run.get("status").and_then(Value::as_str) == Some("completed")
        && run.get("tool").and_then(Value::as_str) == Some(tool);
    if !matches {
        return None;
    }
    Some((
        run.get("runId").and_then(Value::as_str)?.to_string(),
        run.get("completedAtUnix").and_then(Value::as_u64),
    ))
}

struct RunScope {
    scope_file: Option<String>,
    paths: Vec<String>,
}

fn run_scope(run_dir: &Path) -> Option<RunScope> {
    let body =
        crate::bounded_file::read_utf8_text(&run_dir.join("input.json"), MAX_INPUT_JSON_BYTES)
            .ok()?;
    let input: Value = serde_json::from_str(&body).ok()?;
    let paths = input
        .get("paths")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Some(RunScope {
        scope_file: input
            .get("scopeFile")
            .and_then(Value::as_str)
            .map(str::to_string),
        paths,
    })
}

/// Two match signals: the run consumed a campaign-materialized scope file
/// named after this shard (`…/scope/<shard>.txt` — how a TUI-launched job
/// tool run identifies itself), or an explicit run path overlaps a shard
/// path in either prefix direction.
fn scope_matches_shard(scope: &RunScope, shard: &str, shard_paths: &[String]) -> bool {
    if let Some(scope_file) = &scope.scope_file {
        if scope_file_names_shard(scope_file, shard) {
            return true;
        }
    }
    scope.paths.iter().any(|run_path| {
        shard_paths
            .iter()
            .any(|shard_path| paths_overlap(run_path, shard_path))
    })
}

fn scope_file_names_shard(scope_file: &str, shard: &str) -> bool {
    let path = Path::new(scope_file);
    let stem_matches = path.file_stem().is_some_and(|stem| stem == shard);
    let under_scope_dir = path
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|dir| dir == "scope");
    stem_matches && under_scope_dir
}

fn paths_overlap(left: &str, right: &str) -> bool {
    let left = left.trim_end_matches('/');
    let right = right.trim_end_matches('/');
    left == right
        || left.starts_with(&format!("{right}/"))
        || right.starts_with(&format!("{left}/"))
}

/// One row per shard, keeping the most recently completed overlapping run.
fn record_latest(
    overlaps: &mut Vec<PriorScanOverlap>,
    shard: &str,
    run_id: &str,
    completed_at_unix: Option<u64>,
) {
    if let Some(existing) = overlaps.iter_mut().find(|overlap| overlap.shard == shard) {
        if completed_at_unix > existing.completed_at_unix {
            existing.run_id = run_id.to_string();
            existing.completed_at_unix = completed_at_unix;
        }
        return;
    }
    overlaps.push(PriorScanOverlap {
        shard: shard.to_string(),
        run_id: run_id.to_string(),
        completed_at_unix,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn write_run(root: &Path, run_id: &str, kind: &str, status: &str, tool: &str, input: Value) {
        let dir = root.join(".kuzushi/v3/runs").join(run_id);
        std::fs::create_dir_all(&dir).unwrap();
        let run = json!({
            "runId": run_id,
            "kind": kind,
            "status": status,
            "tool": tool,
            "completedAtUnix": 1_784_642_182u64,
        });
        std::fs::write(dir.join("run.json"), run.to_string()).unwrap();
        std::fs::write(dir.join("input.json"), input.to_string()).unwrap();
    }

    #[test]
    fn completed_direct_run_with_matching_shard_scope_file_is_reported() {
        let temp = tempfile::tempdir().unwrap();
        write_run(
            temp.path(),
            "tool-1784641298165-829fc68126f7",
            "tool",
            "completed",
            "agentic-sast:scan",
            json!({"scopeFile": ".kuzushi/v3/campaigns/tuiloop-c12/scope/py-tb-sed.txt"}),
        );

        let shards = vec![("py-tb-sed".to_string(), vec!["src/py/security".to_string()])];
        let overlaps = prior_scan_overlaps(temp.path(), "agentic-sast:scan", &shards);

        assert_eq!(overlaps.len(), 1);
        assert_eq!(overlaps[0].shard, "py-tb-sed");
        assert_eq!(overlaps[0].run_id, "tool-1784641298165-829fc68126f7");
    }

    #[test]
    fn campaign_runs_failed_runs_and_other_tools_never_overlap() {
        let temp = tempfile::tempdir().unwrap();
        let scope = json!({"scopeFile": "x/scope/py-tb-sed.txt"});
        write_run(
            temp.path(),
            "job-001-a1",
            "run",
            "completed",
            "agentic-sast:scan",
            scope.clone(),
        );
        write_run(
            temp.path(),
            "tool-2",
            "tool",
            "failed",
            "agentic-sast:scan",
            scope.clone(),
        );
        write_run(
            temp.path(),
            "tool-3",
            "tool",
            "completed",
            "taint-iris:hunt",
            scope,
        );

        let shards = vec![("py-tb-sed".to_string(), Vec::new())];
        assert!(prior_scan_overlaps(temp.path(), "agentic-sast:scan", &shards).is_empty());
    }

    #[test]
    fn explicit_run_paths_overlap_shard_paths_in_either_prefix_direction() {
        let temp = tempfile::tempdir().unwrap();
        write_run(
            temp.path(),
            "tool-4",
            "tool",
            "completed",
            "agentic-sast:scan",
            json!({"paths": ["src/py/security/devices"]}),
        );

        let broader = vec![("broad".to_string(), vec!["src/py".to_string()])];
        let narrower = vec![(
            "narrow".to_string(),
            vec!["src/py/security/devices/sed.py".to_string()],
        )];
        let disjoint = vec![("other".to_string(), vec!["src/go".to_string()])];

        assert_eq!(
            prior_scan_overlaps(temp.path(), "agentic-sast:scan", &broader).len(),
            1
        );
        assert_eq!(
            prior_scan_overlaps(temp.path(), "agentic-sast:scan", &narrower).len(),
            1
        );
        assert!(prior_scan_overlaps(temp.path(), "agentic-sast:scan", &disjoint).is_empty());
    }
}
