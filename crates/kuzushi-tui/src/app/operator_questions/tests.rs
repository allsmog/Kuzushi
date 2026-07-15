use super::*;
use crate::WorkerGeneration;
use crossterm::event::KeyCode;
use std::sync::mpsc::sync_channel;

fn card_with_channel() -> (
    PendingOperatorQuestion,
    std::sync::mpsc::Receiver<OperatorQuestionControl>,
) {
    let (tx, rx) = sync_channel(8);
    (
        PendingOperatorQuestion::new(OperatorQuestionEnvelope {
            request: request(),
            generation: WorkerGeneration::new(7),
            control: tx,
        }),
        rx,
    )
}

fn receive_resolution(
    rx: &std::sync::mpsc::Receiver<OperatorQuestionControl>,
) -> OperatorQuestionResolution {
    loop {
        if let OperatorQuestionControl::Resolve { resolution, .. } = rx.recv().unwrap() {
            return resolution;
        }
    }
}

fn request() -> OperatorQuestionRequest {
    OperatorQuestionRequest {
        request_id: "q-1".to_string(),
        run_id: "run-1".to_string(),
        questions: vec![OperatorQuestion {
            id: "scope".to_string(),
            header: "Scope".to_string(),
            prompt: "What should Scan inspect?".to_string(),
            options: vec![
                OperatorQuestionOption {
                    label: "Changed files".to_string(),
                    description: "Fast focused scan".to_string(),
                    recommended: true,
                },
                OperatorQuestionOption {
                    label: "Repository".to_string(),
                    description: "Broad scan".to_string(),
                    recommended: false,
                },
            ],
        }],
        auto_resolution_ms: None,
    }
}

#[test]
fn validates_contract_and_rejects_short_timeout() {
    assert!(request().validate().is_ok());
    let mut invalid = request();
    invalid.auto_resolution_ms = Some(59_999);
    assert!(invalid.validate().is_err());
}

#[test]
fn card_submits_predefined_without_persisting_other_text_itself() {
    let (mut card, rx) = card_with_channel();
    assert!(card.submit_current());
    let answer = receive_resolution(&rx);
    assert_eq!(answer.kind, OperatorQuestionResolutionKind::Submitted);
    assert!(matches!(
        &answer.answers[0],
        OperatorQuestionAnswer::Predefined { label, .. } if label == "Changed files"
    ));
}

#[test]
fn validation_requires_one_recommendation_and_other_requires_text() {
    let mut invalid = request();
    invalid.questions[0].options[1].recommended = true;
    assert!(invalid.validate().is_err());

    let (mut card, rx) = card_with_channel();
    card.open_other();
    assert!(!card.submit_current());
    assert!(matches!(
        rx.try_recv(),
        Ok(OperatorQuestionControl::SnoozeAutoResolution { .. })
    ));
    card.edit_other(KeyCode::Char('x'));
    assert!(card.submit_current());
    assert!(matches!(
        &receive_resolution(&rx).answers[0],
        OperatorQuestionAnswer::Freeform { text, .. } if text == "x"
    ));
}

#[test]
fn multiline_other_answer_round_trips_through_one_placeholder() {
    let (mut card, rx) = card_with_channel();
    card.open_other();
    assert!(card.paste_other("src/auth.rs\nonly changed functions"));
    assert!(card.other_editor().unwrap().contains("paste #1"));

    assert!(card.submit_current());

    assert!(matches!(
        &receive_resolution(&rx).answers[0],
        OperatorQuestionAnswer::Freeform { text, .. }
            if text == "src/auth.rs\nonly changed functions"
    ));
}

#[test]
fn out_of_range_number_does_not_select_the_recommended_fallback() {
    let (mut card, rx) = card_with_channel();
    assert!(!card.select_number(3));
    assert!(matches!(
        rx.try_recv(),
        Ok(OperatorQuestionControl::SnoozeAutoResolution { .. })
    ));
}

#[test]
fn credential_collection_is_routed_but_secret_scan_scope_is_not() {
    let mut credential = request();
    credential.questions[0].id = "auth_method".to_string();
    credential.questions[0].header = "Auth".to_string();
    credential.questions[0].prompt = "Paste an API key or choose OAuth".to_string();
    credential.questions[0].options[0].label = "API key".to_string();
    credential.questions[0].options[1].label = "OAuth".to_string();
    assert!(credential.requires_credential_route());

    let mut secret_scan = request();
    secret_scan.questions[0].prompt =
        "Should Scan inspect source files for leaked credentials and secret keys?".to_string();
    secret_scan.questions[0].options[0].label = "Changed files".to_string();
    secret_scan.questions[0].options[1].label = "Repository".to_string();
    assert!(!secret_scan.requires_credential_route());
}
