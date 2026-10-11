use super::*;
use serde_json::json;

fn case() -> CaseResourceEvidenceV1 {
    CaseResourceEvidenceV1 {
        case_id: "owned".into(),
        equivalence_sha256: "conditions".into(),
        passes: 3,
        run_ids: Vec::new(),
        calls_per_pass: None,
        cost_per_pass_usd: None,
        limitations: Vec::new(),
    }
}

#[test]
fn uncertain_prices_do_not_hide_observed_request_ranges() {
    let mut result = case();
    apply_observations(&mut result, &[(Some(2), Some(1.0)), (Some(4), None)]);
    assert_eq!(result.calls_per_pass, Some([2, 4]));
    assert!(result.cost_per_pass_usd.is_none());
    apply_observations(&mut result, &[(None, Some(1.0)), (Some(4), Some(2.0))]);
    assert!(result.calls_per_pass.is_none());
}

#[test]
fn empty_observations_are_not_zero_consumption() {
    let mut result = case();
    apply_observations(&mut result, &[]);
    assert!(result.calls_per_pass.is_none() && result.cost_per_pass_usd.is_none());
}

#[test]
fn baseline_choices_refuse_self_reference_and_mixed_usage_sources() {
    let plan = json!({"campaignId":"new"});
    assert!(selected_baseline(&json!({"resourceBaselineCampaignId":"new"}), &plan).is_err());
    assert!(selected_baseline(&json!({"resourceBaselineCampaignId":"../outside"}), &plan).is_err());
    assert!(selected_baseline(
        &json!({"resourceBaselineCampaignId":"prior","baselineRunId":"run"}),
        &plan
    )
    .is_err());
    assert_eq!(selected_baseline(&json!({}), &plan).unwrap(), None);
}

#[test]
fn queue_reads_are_bounded_and_never_follow_a_symlink() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join(".kuzushi/v3/campaigns/prior");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("queue.json");
    std::fs::write(&path, vec![b' '; METADATA_BYTES + 1]).unwrap();
    assert!(bounded_queue(root.path(), "prior").is_err());
    std::fs::remove_file(&path).unwrap();
    #[cfg(unix)]
    {
        let other = root.path().join("owned-other.json");
        std::fs::write(&other, "{\"jobs\":{}}").unwrap();
        std::os::unix::fs::symlink(other, &path).unwrap();
        assert!(bounded_queue(root.path(), "prior").is_err());
    }
}
