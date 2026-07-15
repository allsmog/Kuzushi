use super::{OperatorQuestion, OperatorQuestionOption};

pub(super) fn question_requests_credentials(question: &OperatorQuestion) -> bool {
    let header_and_id = format!("{} {}", question.header, question.id).to_ascii_lowercase();
    if credential_header(&header_and_id) {
        return true;
    }
    let prompt = question.prompt.to_ascii_lowercase();
    credential_collection_prompt(&prompt) || credential_method_options(&question.options)
}

fn credential_header(text: &str) -> bool {
    CREDENTIAL_HEADER_TERMS
        .iter()
        .any(|term| text.contains(term))
}

fn credential_collection_prompt(text: &str) -> bool {
    contains_term(text, CREDENTIAL_VALUE_TERMS) && contains_term(text, COLLECTION_TERMS)
}

fn contains_term(text: &str, terms: &[&str]) -> bool {
    terms.iter().any(|term| text.contains(term))
}

fn credential_method_options(options: &[OperatorQuestionOption]) -> bool {
    let text = options
        .iter()
        .map(|option| format!("{} {}", option.label, option.description))
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    let api_key = text.contains("api key") || text.contains("api-key");
    let delegated_auth = text.contains("oauth") || text.contains("browser login");
    api_key && delegated_auth
}

const CREDENTIAL_HEADER_TERMS: &[&str] = &[
    "credential",
    "api key",
    "api_key",
    "password",
    "passphrase",
    "access token",
    "auth token",
    "auth ",
    "auth_",
    "oauth",
    "login",
    "sign in",
];

const CREDENTIAL_VALUE_TERMS: &[&str] = &[
    "credential",
    "api key",
    "api-key",
    "password",
    "passphrase",
    "access token",
    "auth token",
    "oauth token",
    "private key",
    "secret key",
];

const COLLECTION_TERMS: &[&str] = &[
    "paste", "enter", "provide", "supply", "share", "type", "submit", "input", "send",
];
