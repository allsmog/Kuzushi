use super::safe_text::sanitize_for_log_line;
use super::scan_output::{scan_cost_usd, scan_findings_count};
use std::path::Path;
use std::time::{Duration, Instant};

pub(crate) fn emit_scan_ci_error(
    ci: bool,
    started: Instant,
    elapsed: Duration,
    error: &anyhow::Error,
) {
    if ci {
        println!(
            "{}",
            ci_line(
                started,
                "phase",
                &format!("scanning → failed ({})", format_duration(elapsed))
            )
        );
        // Error chains can carry LLM-derived text (e.g. bridge response
        // bodies). Strip control characters so an embedded `\n[+0.0s] exit: 0`
        // can't spoof a fake success line under our prefix.
        println!(
            "{}",
            ci_line(started, "error", &sanitize_for_log_line(&error.to_string()))
        );
        println!("{}", ci_line(started, "exit", "1"));
    }
}

pub(crate) fn emit_scan_ci_success(
    result: &serde_json::Value,
    data: &serde_json::Value,
    started: Instant,
    elapsed: Duration,
) {
    println!(
        "{}",
        ci_line(
            started,
            "phase",
            &format!("scanning → done ({})", format_duration(elapsed))
        )
    );
    println!(
        "{}",
        ci_line(
            started,
            "summary",
            &format!(
                "{} finding(s) · ${:.4} · {}",
                scan_findings_count(data),
                scan_cost_usd(result),
                format_duration(elapsed)
            )
        )
    );
    emit_scan_ci_warnings(result, started);
    println!("{}", ci_line(started, "exit", "0"));
}

fn emit_scan_ci_warnings(result: &serde_json::Value, started: Instant) {
    let Some(warnings) = result.get("warnings").and_then(serde_json::Value::as_array) else {
        return;
    };
    for warning in warnings.iter().filter_map(serde_json::Value::as_str) {
        println!(
            "{}",
            ci_line(started, "warning", &sanitize_for_log_line(warning))
        );
    }
}

pub(crate) fn emit_scan_ci_start(
    ci: bool,
    started: Instant,
    target: &Path,
    config: &kuzushi_core::V2Config,
    tasks: &[String],
) {
    if ci {
        println!(
            "{}",
            ci_line(started, "scan", &scan_started_body(target, config, tasks))
        );
        println!("{}", ci_line(started, "phase", "(init) → scanning"));
    }
}

pub(crate) fn scan_started_body(
    target: &Path,
    config: &kuzushi_core::V2Config,
    tasks: &[String],
) -> String {
    format!(
        "{} started [model={} tasks={}]",
        target.display(),
        config.model.as_deref().unwrap_or("unconfigured"),
        scan_tasks_label(tasks),
    )
}

pub(crate) fn scan_tasks_label(tasks: &[String]) -> String {
    if tasks.is_empty() {
        "auto".to_string()
    } else {
        tasks.join(",")
    }
}

pub(crate) fn ci_line(started: Instant, prefix: &str, body: &str) -> String {
    let elapsed = started.elapsed();
    format!("[+{:.1}s] {prefix}: {body}", elapsed.as_secs_f64())
}

pub(crate) fn format_duration(elapsed: Duration) -> String {
    let secs = elapsed.as_secs();
    if secs >= 60 {
        let minutes = secs / 60;
        let rem = secs % 60;
        format!("{minutes}m {rem}s")
    } else {
        format!("{:.1}s", elapsed.as_secs_f64())
    }
}
