use crate::run_lifecycle::{RunQuestionId, SafeText};
use sha2::{Digest, Sha256};

const QUESTION_ID_NAMESPACE: &str = "kuzushi.run-question.v1";
const CHOICE_ID_NAMESPACE: &str = "kuzushi.run-question-choice.v1";

/// Derive the persisted question identity from stable request-local identity.
/// Prompt or option text is intentionally excluded so operator-visible copy is
/// never promoted into a correlation key.
pub fn deterministic_question_id(
    request_identity: &str,
    question_identity: &str,
    question_ordinal: usize,
) -> RunQuestionId {
    let digest = identity_digest(
        QUESTION_ID_NAMESPACE,
        request_identity,
        question_identity,
        question_ordinal,
        None,
    );
    RunQuestionId::parse(&uuid_from_digest(digest))
        .expect("a deterministic question digest always forms a UUID")
}

/// Derive one stable choice identity without relying on its mutable label.
pub fn deterministic_choice_id(
    request_identity: &str,
    question_identity: &str,
    question_ordinal: usize,
    choice_ordinal: usize,
) -> SafeText {
    let digest = identity_digest(
        CHOICE_ID_NAMESPACE,
        request_identity,
        question_identity,
        question_ordinal,
        Some(choice_ordinal),
    );
    SafeText::operator_visible(format!("choice-{}", hex_prefix(&digest, 16)))
}

fn identity_digest(
    namespace: &str,
    request_identity: &str,
    question_identity: &str,
    question_ordinal: usize,
    choice_ordinal: Option<usize>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    append_component(&mut digest, namespace.as_bytes());
    append_component(&mut digest, request_identity.as_bytes());
    append_component(&mut digest, question_identity.as_bytes());
    append_component(&mut digest, &question_ordinal.to_be_bytes());
    if let Some(choice_ordinal) = choice_ordinal {
        append_component(&mut digest, &choice_ordinal.to_be_bytes());
    }
    digest.finalize().into()
}

fn append_component(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn uuid_from_digest(mut digest: [u8; 32]) -> String {
    digest[6] = (digest[6] & 0x0f) | 0x50;
    digest[8] = (digest[8] & 0x3f) | 0x80;
    let hex = hex_prefix(&digest, 16);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn hex_prefix(bytes: &[u8], count: usize) -> String {
    bytes
        .iter()
        .take(count)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn question_and_choice_identity_is_stable_and_copy_independent() {
        let question = deterministic_question_id("request-7", "scope", 0);
        let repeated = deterministic_question_id("request-7", "scope", 0);
        let next_question = deterministic_question_id("request-7", "scope", 1);
        let first_choice = deterministic_choice_id("request-7", "scope", 0, 0);
        let second_choice = deterministic_choice_id("request-7", "scope", 0, 1);

        assert_eq!(question, repeated);
        assert_ne!(question, next_question);
        assert_ne!(first_choice, second_choice);
        assert_eq!(first_choice.as_str().len(), "choice-".len() + 32);
    }
}
