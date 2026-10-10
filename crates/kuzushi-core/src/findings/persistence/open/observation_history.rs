//! Bounded recorded observations for derived history consumers.
use super::*;

impl FindingStore {
    pub(crate) fn observation_history_window(
        &self,
        max_rows: usize,
        max_bytes: usize,
    ) -> Result<Vec<(u64, Finding)>> {
        let mut statement = self.conn.prepare(
            "select created_seq, run_id, finding_json, length(cast(finding_json as blob))
             from finding_observations order by created_seq limit ?1",
        )?;
        let limit = i64::try_from(max_rows.saturating_add(1))?;
        let mut rows = statement.query([limit])?;
        let mut observations = Vec::new();
        let mut bytes = 0usize;
        while let Some(row) = rows.next()? {
            anyhow::ensure!(
                observations.len() < max_rows,
                "observation history exceeds {max_rows} rows"
            );
            let size: Option<i64> = row.get(3)?;
            let size = size.context("recorded observation payload is unavailable")?;
            bytes = bytes
                .checked_add(usize::try_from(size)?)
                .context("observation byte count overflow")?;
            anyhow::ensure!(
                bytes <= max_bytes,
                "observation history exceeds {max_bytes} payload bytes"
            );
            let mut finding: Finding = serde_json::from_str(&row.get::<_, String>(2)?)
                .context("recorded observation payload is malformed")?;
            finding.scan_id = Some(row.get(1)?);
            observations.push((u64::try_from(row.get::<_, i64>(0)?)?, finding));
        }
        Ok(observations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, FindingStore) {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".kuzushi/v3")).unwrap();
        let store =
            FindingStore::open(crate::workspace::workspace_findings_db_path(root.path())).unwrap();
        for run in ["base", "head"] {
            store
                .insert_scan_run(run, root.path(), "completed")
                .unwrap();
            let mut finding = Finding::new_tool(
                "owned-policy",
                "license-policy",
                "package.json",
                1,
                None,
                crate::findings::Severity::Low,
                "Owned policy observation",
            );
            finding.scan_id = Some(run.into());
            store.insert_finding(run, &finding).unwrap();
        }
        (root, store)
    }

    #[test]
    fn observation_history_uses_each_recorded_run_and_refuses_truncation() {
        let (_root, store) = store();
        let rows = store.observation_history_window(2, 1024 * 1024).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].1.scan_id.as_deref(), Some("base"));
        assert_eq!(rows[1].1.scan_id.as_deref(), Some("head"));
        assert!(rows[0].0 < rows[1].0);
        assert!(store
            .observation_history_window(1, 1024 * 1024)
            .unwrap_err()
            .to_string()
            .contains("exceeds 1 rows"));
        assert!(store
            .observation_history_window(2, 1)
            .unwrap_err()
            .to_string()
            .contains("payload bytes"));
        assert_eq!(
            store
                .observation_history_window(2, 1024 * 1024)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn unavailable_or_malformed_history_is_rejected_without_repair() {
        for (payload, message) in [(None, "unavailable"), (Some("{}"), "malformed")] {
            let (_root, store) = store();
            store
                .conn
                .execute("update finding_observations set finding_json=?1", [payload])
                .unwrap();
            let error = store
                .observation_history_window(2, 1024 * 1024)
                .unwrap_err();
            assert!(error.to_string().contains(message));
            let after: Option<String> = store
                .conn
                .query_row(
                    "select finding_json from finding_observations limit 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(after.as_deref(), payload);
        }
    }
}
