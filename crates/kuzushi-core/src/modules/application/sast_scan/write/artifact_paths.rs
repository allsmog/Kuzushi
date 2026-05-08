use super::*;

impl WhiteboxArtifacts {
    pub(in crate::modules) fn artifact_paths(
        &self,
        artifacts: &SastRunArtifacts,
    ) -> WhiteboxArtifactPaths {
        WhiteboxArtifactPaths {
            static_narratives: artifact_path_if_present(
                &self.static_narratives,
                artifacts,
                "static-narratives.json",
            ),
            static_variants: artifact_path_if_present(
                &self.static_variants,
                artifacts,
                "static-variants.json",
            ),
            candidate_semgrep_rules: artifact_path_if_present(
                &self.candidate_semgrep_rules,
                artifacts,
                "candidate-semgrep-rules.json",
            ),
            whitebox_suppressions: artifact_path_if_present(
                &self.whitebox_suppressions,
                artifacts,
                "whitebox-suppressions.json",
            ),
            whitebox_diff: artifact_path_if_present(
                &self.whitebox_diff,
                artifacts,
                "whitebox-diff-scope.json",
            ),
        }
    }
}
