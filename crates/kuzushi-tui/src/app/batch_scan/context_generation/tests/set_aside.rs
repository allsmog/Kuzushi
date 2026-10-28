use super::*;

fn finish_generation(app: &mut ShellApp) {
    let receipt = serde_json::from_value(json!({
        "campaignId": "context-study-1",
        "investigationId": "investigation-1",
        "planSha256": "sha256:00",
        "sourceIdentity": "git:abc",
        "configSha256": "sha256:00",
        "model": "openai-codex:gpt-5.5",
        "input": {}
    }))
    .unwrap();
    let generated = serde_json::from_value(json!({
        "modelId": "tm_1",
        "revisionId": "tmr_1",
        "sha256": "sha256:00"
    }))
    .unwrap();
    let generation = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .and_then(|config| config.context_generation.as_mut())
        .unwrap();
    generation.record_receipt(receipt);
    generation.generated = Some(generated);
}

#[test]
fn a_finished_study_is_set_aside_for_regeneration() {
    let (_root, mut app) = fixture();
    finish_generation(&mut app);

    app.set_aside_finished_study();

    assert!(app.router.campaign().batch_scan_config.is_none());
}

#[test]
fn a_study_without_a_result_stays_open() {
    let (_root, mut app) = fixture();

    app.set_aside_finished_study();

    assert!(app.router.campaign().batch_scan_config.is_some());
}
