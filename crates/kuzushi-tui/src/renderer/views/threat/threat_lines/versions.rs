use super::*;
use kuzushi_core::findings::ThreatModelVersionRecord;

pub(super) fn append_version_lines(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    let threat = app.router.threat();
    lines.push(section_header_line("THREAT MODEL VERSIONS", area.width));
    if threat.versions().is_empty() {
        lines.push(detail(
            "versions",
            "none recorded yet; a threat-model build appends one automatically",
        ));
    }
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    for version in threat.versions() {
        lines.push(detail(
            &format!("#{}", version.id),
            &version_row(version, threat.live_sha256(), now_secs),
        ));
    }
    lines.push(blank());

    lines.push(section_header_line("ACTIONS", area.width));
    lines.push(detail("select", "/threats use <id>"));
    lines.push(detail("refresh", "/threats versions"));
}

fn version_row(
    version: &ThreatModelVersionRecord,
    live_sha256: Option<&str>,
    now_secs: u64,
) -> String {
    let live = if live_sha256 == Some(version.sha256.as_str()) {
        " · LIVE"
    } else {
        ""
    };
    let run = version
        .run_id
        .as_deref()
        .map(|run_id| format!(" · run {run_id}"))
        .unwrap_or_default();
    format!(
        "{} · {} · {} · {} threat(s) · {}{}{}",
        version_age(&version.created_at, now_secs),
        version.source,
        version.methodology,
        version.threat_count,
        short_sha(&version.sha256),
        run,
        live,
    )
}

/// The ledger stores epoch seconds (store convention); render a relative
/// age. Unparseable stamps render verbatim rather than inventing an age.
fn version_age(created_at: &str, now_secs: u64) -> String {
    let Ok(created_secs) = created_at.parse::<u64>() else {
        return created_at.to_string();
    };
    let age = now_secs.saturating_sub(created_secs);
    match age {
        0..=59 => format!("{age}s ago"),
        60..=3599 => format!("{}m ago", age / 60),
        3600..=86399 => format!("{}h ago", age / 3600),
        _ => format!("{}d ago", age / 86400),
    }
}

fn short_sha(sha256: &str) -> String {
    let hex = sha256.strip_prefix("sha256:").unwrap_or(sha256);
    hex.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(id: i64, sha: &str) -> ThreatModelVersionRecord {
        ThreatModelVersionRecord {
            id,
            created_at: "1000".to_string(),
            source: "build".to_string(),
            run_id: Some("run-9".to_string()),
            model_id: None,
            revision_id: None,
            methodology: "stride".to_string(),
            threat_count: 15,
            sha256: format!("sha256:{sha}"),
        }
    }

    #[test]
    fn version_row_marks_the_live_document_and_shortens_the_hash() {
        let row = version(3, "abcdef0123456789");

        let live = version_row(&row, Some("sha256:abcdef0123456789"), 8_200);
        let stale = version_row(&row, Some("sha256:other"), 8_200);

        assert!(live.starts_with("2h ago"), "{live}");
        assert!(live.ends_with(" · LIVE"), "{live}");
        assert!(live.contains("abcdef012345"), "{live}");
        assert!(live.contains("run run-9"), "{live}");
        assert!(!stale.contains("LIVE"), "{stale}");
    }

    #[test]
    fn version_age_covers_units_and_keeps_unparseable_stamps_verbatim() {
        assert_eq!(version_age("100", 130), "30s ago");
        assert_eq!(version_age("0", 7_200), "2h ago");
        assert_eq!(version_age("0", 172_800), "2d ago");
        assert_eq!(
            version_age("2026-07-22T10:00:00Z", 0),
            "2026-07-22T10:00:00Z"
        );
    }
}
