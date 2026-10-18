use super::*;

impl FindingStore {
    /// Read current finding paths without hydrating findings or merged sources.
    /// The limit bounds returned rows, not SQLite's identity-folding work.
    pub(crate) fn recommendation_finding_paths_with_cancellation(
        &self,
        limit: usize,
        cancellation: Option<&crate::ScanCancellation>,
    ) -> Result<Vec<String>> {
        crate::sqlite_read_control::read(&self.conn, cancellation, || {
            self.read_recommendation_paths(limit)
        })
    }

    fn read_recommendation_paths(&self, limit: usize) -> Result<Vec<String>> {
        let mut statement = self.conn.prepare(LATEST_FINDING_PATHS_SQL)?;
        let rows = statement.query_map([limit.saturating_add(1) as i64], |row| row.get(0))?;
        let paths = rows
            .collect::<rusqlite::Result<Vec<String>>>()
            .context("Could not read finding paths for recommendations")?;
        anyhow::ensure!(paths.len() <= limit,
            "finding history exceeds the {limit}-row recommendation read limit; select a smaller target or archive history");
        Ok(paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canceled_path_read_is_refused_and_the_connection_can_be_reused() {
        let store = FindingStore::open_in_memory().unwrap();
        let cancellation = crate::ScanCancellation::default();
        cancellation.cancel();
        assert!(store
            .recommendation_finding_paths_with_cancellation(10, Some(&cancellation))
            .unwrap_err()
            .to_string()
            .contains("cancelled"));
        assert!(store
            .recommendation_finding_paths_with_cancellation(10, None)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn paths_match_latest_projection_and_exhaustion_is_explicit() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("owned-paths", Path::new("/tmp"), "running")
            .unwrap();
        for (index, path) in ["src/first.rs", "src/second.rs", "src/third.rs"]
            .iter()
            .enumerate()
        {
            let finding = Finding::new_tool(
                "owned-metadata",
                &format!("rule-{index}"),
                *path,
                1,
                Some(1),
                Severity::Low,
                "Synthetic recommendation path fixture",
            );
            store.insert_finding("owned-paths", &finding).unwrap();
        }
        let expected: std::collections::BTreeSet<_> = store
            .list_all_findings()
            .unwrap()
            .into_iter()
            .map(|finding| finding.file_path)
            .collect();
        let actual = store
            .recommendation_finding_paths_with_cancellation(3, None)
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(expected, actual);
        let error = store
            .recommendation_finding_paths_with_cancellation(2, None)
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("2-row recommendation read limit"));
    }
}
