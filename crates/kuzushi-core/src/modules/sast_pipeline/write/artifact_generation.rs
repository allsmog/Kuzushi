use super::*;

impl WhiteboxArtifacts {
    pub(in crate::modules) fn write(
        enabled: bool,
        input: &Value,
        workspace: &crate::workspace::WorkspaceTarget,
        store: &crate::findings::FindingStore,
        run_ids: &SastRunIds,
        artifacts: &SastRunArtifacts,
    ) -> Result<Self> {
        if !enabled {
            return Ok(Self::default());
        }

        let static_ranking = Some(write_static_ranking_json(
            workspace, store, run_ids, artifacts,
        )?);
        let static_narratives = Some(write_static_narratives_json(
            store,
            run_ids,
            artifacts,
            static_ranking.as_ref(),
        )?);
        let whitebox_diff = match string_input_any(input, &["diffBase", "diff_base"]) {
            Some(diff_base) => Some(write_whitebox_diff_scope_json(
                workspace, store, run_ids, artifacts, &diff_base,
            )?),
            None => None,
        };

        Ok(Self {
            static_ranking,
            static_narratives,
            static_variants: Some(write_static_variants_json(
                workspace, store, run_ids, artifacts,
            )?),
            candidate_semgrep_rules: Some(write_candidate_semgrep_rules_json(
                workspace, store, run_ids, artifacts,
            )?),
            whitebox_suppressions: Some(write_whitebox_suppressions_json(
                workspace, store, run_ids, artifacts,
            )?),
            whitebox_diff,
        })
    }
}
