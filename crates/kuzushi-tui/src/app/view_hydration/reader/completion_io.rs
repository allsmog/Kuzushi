use super::*;

const RECENT_RUN_COMPLETION_LIMIT: usize = 100;

pub(super) fn read_completion_value(
    target: &Path,
    key: &ViewHydrationKey,
) -> Option<ViewHydrationValue> {
    match key {
        ViewHydrationKey::FileCompletionValues => {
            let index =
                crate::app::workspace_file_candidates(target, crate::app::FILE_PICKER_MAX_FILES);
            Some(ViewHydrationValue::FileCompletionValues(index))
        }
        ViewHydrationKey::FindingCompletionValues => {
            Some(ViewHydrationValue::FindingCompletionValues(
                crate::app::load_finding_completion_values(target),
            ))
        }
        ViewHydrationKey::RunIdCompletionValues => {
            Some(ViewHydrationValue::RunIdCompletionValues(run_ids(target)))
        }
        _ => None,
    }
}

fn run_ids(target: &Path) -> Vec<String> {
    let mut values =
        kuzushi_core::list_recent_run_summary_entries(target, RECENT_RUN_COMPLETION_LIMIT)
            .unwrap_or_default()
            .into_iter()
            .filter(run_entry_was_directory)
            .map(|entry| entry.run_id)
            .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn run_entry_was_directory(entry: &kuzushi_core::RunSummaryEntry) -> bool {
    !matches!(
        &entry.state,
        kuzushi_core::RunSummaryEntryState::Issue(
            kuzushi_core::RunSummaryIssue::NotDirectory
                | kuzushi_core::RunSummaryIssue::UnsafeSymlink
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_id_hydration_is_bounded_to_the_recent_page() {
        let target = tempfile::tempdir().unwrap();
        seed_run_history(target.path(), 125);

        let values = run_ids(target.path());

        assert_eq!(values.len(), RECENT_RUN_COMPLETION_LIMIT);
        assert!(values.contains(&"run-124".to_string()));
        assert!(!values.contains(&"run-000".to_string()));
    }

    fn seed_run_history(target: &Path, count: u64) {
        for index in 0..count {
            let run_id = format!("run-{index:03}");
            let mut summary = kuzushi_core::RunSummary::running(
                &run_id,
                "tool",
                None,
                target.display().to_string(),
            )
            .complete();
            summary.started_at_unix = index;
            summary.completed_at_unix = Some(index);
            let run_dir = kuzushi_core::run_dir(target, &run_id);
            std::fs::create_dir_all(&run_dir).unwrap();
            std::fs::write(
                run_dir.join("run.json"),
                serde_json::to_vec(&summary).unwrap(),
            )
            .unwrap();
        }
    }
}
