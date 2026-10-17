use super::*;

fn report(title: &str) -> Value {
    json!({"leadCount":1,"leads":[{"threatId":"T1","title":title}],
        "sourceCoverage":{"schemaVersion":1,"status":"bounded","completeRepositoryCoverage":false}})
}

fn seed(target: &Path, value: &Value) {
    std::fs::create_dir_all(target.join(".kuzushi")).unwrap();
    std::fs::write(threat_leads_artifact_path(target), value.to_string()).unwrap();
    std::fs::write(
        threat_leads_summary_path(target),
        render_threat_leads_markdown(value),
    )
    .unwrap();
}

#[test]
fn interrupted_pair_keeps_committed_json_and_discloses_stale_markdown_until_repair() {
    let root = tempfile::tempdir().unwrap();
    seed(root.path(), &report("Previous owned hints"));
    let next = report("Current owned hints");
    let warning = publish_with(root.path(), &next, &mut |path, bytes| {
        anyhow::ensure!(path.extension().unwrap() != "md", "owned publication fault");
        std::fs::write(path, bytes)?;
        Ok(())
    })
    .unwrap();
    assert!(warning.unwrap().contains("JSON cards were saved"));
    assert_eq!(read_threat_leads(root.path()).unwrap(), next);
    assert!(inspect_summary(root.path(), &next) == SummaryState::Stale);
    let output = tool_output(root.path(), next.clone());
    assert_eq!(output["status"], "partial");
    assert_eq!(output["summaryPublication"]["status"], "stale");
    assert_eq!(output["artifacts"].as_array().unwrap().len(), 1);
    let json_bytes = std::fs::read(threat_leads_artifact_path(root.path())).unwrap();
    repair(root.path(), &next).unwrap();
    assert!(inspect_summary(root.path(), &next) == SummaryState::Current);
    assert_eq!(
        std::fs::read(threat_leads_artifact_path(root.path())).unwrap(),
        json_bytes
    );
}

#[test]
fn failure_before_json_commit_preserves_both_prior_artifacts() {
    let root = tempfile::tempdir().unwrap();
    let old = report("Prior hints");
    seed(root.path(), &old);
    let before = std::fs::read(threat_leads_artifact_path(root.path())).unwrap();
    let mut calls = 0;
    assert!(
        publish_with(root.path(), &report("Next hints"), &mut |_, _| {
            calls += 1;
            anyhow::bail!("owned commit fault")
        })
        .is_err()
    );
    assert_eq!(calls, 1);
    assert_eq!(
        std::fs::read(threat_leads_artifact_path(root.path())).unwrap(),
        before
    );
    assert!(inspect_summary(root.path(), &old) == SummaryState::Current);
}

#[test]
fn invalid_summary_destination_is_rejected_before_replacing_json() {
    let root = tempfile::tempdir().unwrap();
    seed(root.path(), &report("Prior hints"));
    let before = std::fs::read(threat_leads_artifact_path(root.path())).unwrap();
    std::fs::remove_file(threat_leads_summary_path(root.path())).unwrap();
    std::fs::create_dir(threat_leads_summary_path(root.path())).unwrap();
    assert!(publish(root.path(), &report("Next hints")).is_err());
    assert_eq!(
        std::fs::read(threat_leads_artifact_path(root.path())).unwrap(),
        before
    );
    assert!(inspect_summary(root.path(), &report("Prior hints")) == SummaryState::Unreadable);
}

#[test]
fn missing_summary_and_unrecorded_legacy_context_are_repairable_without_rescan() {
    let root = tempfile::tempdir().unwrap();
    let legacy = json!({"leadCount":0,"leads":[]});
    seed(root.path(), &legacy);
    std::fs::remove_file(threat_leads_summary_path(root.path())).unwrap();
    let loaded = read_threat_leads(root.path()).unwrap();
    assert!(inspect_summary(root.path(), &loaded) == SummaryState::Missing);
    repair(root.path(), &loaded).unwrap();
    assert!(inspect_summary(root.path(), &loaded) == SummaryState::Current);
    let text = std::fs::read_to_string(threat_leads_summary_path(root.path())).unwrap();
    assert!(text.contains("legacy-unverified") && text.contains("unrecorded"));
}
