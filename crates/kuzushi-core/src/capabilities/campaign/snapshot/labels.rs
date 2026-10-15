//! Recorded human labels are presentation hints, separate from job identity and state.
use serde_json::Value;

pub(super) fn job_label(plan: &Value, job: &Value) -> Option<String> {
    let (name, passes) = case_name_and_passes(plan, job)?;
    let trial = job["trial"].as_u64()?;
    if !(1..=passes).contains(&trial) {
        return None;
    }
    let name = crate::run_artifacts::bounded_run_diagnostic_line(&name);
    Some(format!("{name} · pass {trial}/{passes}"))
}

fn case_name_and_passes(plan: &Value, job: &Value) -> Option<(String, u64)> {
    let path = match plan["kind"].as_str()? {
        "scope-study" => "/scopeStudy/cases",
        "context-matrix" => "/contextMatrix/cases",
        "scan-batch" => return Some(("Discovery".into(), plan["trialsPlanned"].as_u64()?)),
        _ => return None,
    };
    let id = job["caseId"].as_str()?;
    let case = plan
        .pointer(path)?
        .as_array()?
        .iter()
        .find(|case| case["id"].as_str() == Some(id))?;
    let name = case["label"].as_str()?.trim();
    if name.is_empty() {
        return None;
    }
    Some((name.to_owned(), case["passes"].as_u64()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn case_labels_come_from_the_recorded_case_and_exact_trial() {
        for (kind, key) in [
            ("scope-study", "scopeStudy"),
            ("context-matrix", "contextMatrix"),
        ] {
            let plan = json!({"kind":kind,key:{"cases":[{"id":"opaque-id","label":"Greeting library","passes":3}]}});
            assert_eq!(
                job_label(&plan, &json!({"caseId":"opaque-id","trial":2})).as_deref(),
                Some("Greeting library · pass 2/3")
            );
            for job in [
                json!({"caseId":"other","trial":2}),
                json!({"caseId":"opaque-id","trial":0}),
                json!({"caseId":"opaque-id","trial":4}),
            ] {
                assert!(job_label(&plan, &job).is_none());
            }
        }
    }

    #[test]
    fn missing_legacy_or_malformed_metadata_never_manufactures_a_pass_label() {
        for plan in [
            json!({}),
            json!({"kind":"scan-batch"}),
            json!({"kind":"scope-study","scopeStudy":{"cases":[{"id":"a","label":" ","passes":3}]}}),
        ] {
            assert!(job_label(&plan, &json!({"caseId":"a","trial":1})).is_none());
        }
        assert_eq!(
            job_label(
                &json!({"kind":"scan-batch","trialsPlanned":3}),
                &json!({"trial":3})
            )
            .as_deref(),
            Some("Discovery · pass 3/3")
        );
    }

    #[test]
    fn recorded_names_are_bounded_and_terminal_safe() {
        let plan = json!({"kind":"scope-study","scopeStudy":{"cases":[{"id":"a","label":format!("\u{1b}[2J\n{}", "x".repeat(1000)),"passes":3}]}});
        let label = job_label(&plan, &json!({"caseId":"a","trial":1})).unwrap();
        assert!(!label.chars().any(char::is_control));
        assert!(label.chars().count() < 520);
        assert!(label.ends_with("pass 1/3"));
    }
}
