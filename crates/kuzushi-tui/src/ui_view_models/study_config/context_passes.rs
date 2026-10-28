//! Names, roles and workload for a finite context experiment.
use crate::app::BatchScanConfig;
use kuzushi_core::capabilities::campaign::ContextCaseInput;

pub(super) fn lines(config: &BatchScanConfig) -> Vec<String> {
    let matrix = &config.study.matrix;
    let mut lines = vec![format!(
        "{} cases · {} fixed jobs",
        matrix.cases.len(),
        matrix.planned_jobs()
    )];
    if matrix.baseline_case_id.is_none() {
        lines.push(
            "Baseline not selected. Choose one in Context cases before preparing the plan.".into(),
        );
    }
    lines.extend(
        matrix
            .cases
            .iter()
            .map(|case| case_line(case, matrix.baseline_case_id.as_deref())),
    );
    lines.push(format!("{} passes is the default for newly added context cases. Existing cases keep their own repetitions; p in Context cases edits the selected case. Approval covers the sum of all case jobs.", config.trials));
    lines
}

fn case_line(case: &ContextCaseInput, baseline: Option<&str>) -> String {
    let role = match baseline {
        Some(id) if id == case.id => "Baseline",
        Some(_) => "Candidate",
        None => "Case",
    };
    format!("{role}: {} · {} passes", case.label, case.passes)
}

#[cfg(test)]
mod tests {
    use super::super::{discovery_pass_lines, study_detail_lines, BatchScanConfig};
    use kuzushi_core::capabilities::campaign::ContextCaseInput;
    use serde_json::Value;

    fn experiment() -> BatchScanConfig {
        let mut config = BatchScanConfig::load(std::path::Path::new("/owned-fixture"), None);
        config.trials = 9;
        config.study.matrix.baseline_case_id = Some("alpha".into());
        config.study.matrix.cases = [
            ("alpha", "Alpha baseline", 2),
            ("beta", "Beta candidate", 4),
        ]
        .into_iter()
        .map(|(id, label, passes)| ContextCaseInput {
            id: id.into(),
            label: label.into(),
            passes,
            threat_model_ref: Value::Null,
        })
        .collect();
        config
    }

    #[test]
    fn discovery_overview_names_each_case_and_its_own_workload_without_changing_the_plan() {
        let config = experiment();
        let before = config.clone();
        let text = discovery_pass_lines(&config).join("\n");
        assert!(text.contains("2 cases · 6 fixed jobs"));
        assert!(text.contains("Baseline: Alpha baseline · 2 passes"));
        assert!(text.contains("Candidate: Beta candidate · 4 passes"));
        assert!(text.contains("9 passes is the default for newly added"));
        assert!(!text.contains("9 fresh discovery passes"));
        for width in [36, 56, 76, 92, 116] {
            let text = study_detail_lines(&config, width).join("\n");
            assert!(text.contains("Alpha baseline") && text.contains("Beta candidate"));
        }
        assert_eq!(config, before);
    }

    #[test]
    fn an_unselected_baseline_does_not_label_every_case_as_a_candidate() {
        let mut config = experiment();
        config.study.matrix.baseline_case_id = None;
        let text = discovery_pass_lines(&config).join("\n");
        assert!(text.contains("Baseline not selected"));
        assert!(text.contains("Case: Alpha baseline · 2 passes"));
        assert!(text.contains("Case: Beta candidate · 4 passes"));
        assert!(!text.contains("Candidate:"));
    }
}
