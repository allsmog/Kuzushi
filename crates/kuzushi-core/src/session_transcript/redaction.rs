use super::{SessionEvent, SessionMetadata, SessionRecord, SessionTruncation};
use anyhow::{Context, Result};
use regex::Regex;
use serde_json::{Map, Value};
use std::sync::OnceLock;

const REDACTED: &str = "[REDACTED]";
const MAX_METADATA_ARGV_BYTES: usize = 256 * 1024;

pub(super) fn metadata_payload(metadata: SessionMetadata) -> Result<Value> {
    let mut metadata = metadata;
    metadata.argv = bounded_metadata_argv(sanitized_argv(metadata.argv))?;
    if let Some(git) = metadata.git.as_mut() {
        git.remote = git.remote.take().map(strip_url_credentials);
    }
    sanitized_value(serde_json::to_value(metadata)?)
}

fn bounded_metadata_argv(argv: Vec<String>) -> Result<Vec<String>> {
    let encoded = serde_json::to_vec(&argv)?;
    if encoded.len() <= MAX_METADATA_ARGV_BYTES {
        return Ok(argv);
    }
    let marker = format!(
        "[TRUNCATED argv bytes={} digest={}]",
        encoded.len(),
        blake3::hash(&encoded).to_hex()
    );
    let mut retained = Vec::new();
    let mut retained_bytes = serde_json::to_vec(&marker)?.len();
    for argument in argv {
        let argument_bytes = serde_json::to_vec(&argument)?.len() + 1;
        if retained_bytes + argument_bytes > MAX_METADATA_ARGV_BYTES {
            break;
        }
        retained_bytes += argument_bytes;
        retained.push(argument);
    }
    retained.push(marker);
    Ok(retained)
}

pub(super) fn event_parts(event: SessionEvent) -> Result<(String, Value)> {
    let event = omit_credential_content(event);
    let Value::Object(mut object) = serde_json::to_value(event)? else {
        anyhow::bail!("session event did not serialize as an object");
    };
    let event_type = take_string(&mut object, "type")?;
    let payload = object.remove("data").unwrap_or_else(empty_object);
    Ok((event_type, sanitized_value(payload)?))
}

pub(super) fn encode_bounded(record: &SessionRecord) -> Result<Vec<u8>> {
    let encoded = serde_json::to_vec(record)?;
    if encoded.len() <= super::MAX_SESSION_RECORD_BYTES {
        return with_newline(encoded);
    }
    encode_truncation(record, &encoded)
}

fn encode_truncation(record: &SessionRecord, original: &[u8]) -> Result<Vec<u8>> {
    let truncation = SessionTruncation {
        original_type: record.event_type.clone(),
        original_bytes: original.len(),
        digest: blake3::hash(original).to_hex().to_string(),
    };
    let mut replacement = record.clone();
    replacement.event_type = "truncated".to_string();
    replacement.payload = serde_json::to_value(truncation)?;
    let encoded = serde_json::to_vec(&replacement)?;
    anyhow::ensure!(encoded.len() <= super::MAX_SESSION_RECORD_BYTES);
    with_newline(encoded)
}

fn with_newline(mut encoded: Vec<u8>) -> Result<Vec<u8>> {
    encoded.push(b'\n');
    Ok(encoded)
}

fn omit_credential_content(event: SessionEvent) -> SessionEvent {
    match event {
        SessionEvent::OperatorQuestion {
            question_id,
            kind,
            prompt: _,
        } if credential_kind(&kind) => SessionEvent::OperatorQuestion {
            question_id,
            kind,
            prompt: None,
        },
        SessionEvent::OperatorAnswer {
            question_id,
            kind,
            outcome,
            answer: _,
        } if credential_kind(&kind) => SessionEvent::OperatorAnswer {
            question_id,
            kind,
            outcome,
            answer: None,
        },
        other => other,
    }
}

fn credential_kind(kind: &str) -> bool {
    let kind = kind.to_ascii_lowercase();
    [
        "credential",
        "secret",
        "password",
        "token",
        "api_key",
        "auth",
    ]
    .iter()
    .any(|needle| kind.contains(needle))
}

fn sanitized_argv(argv: Vec<String>) -> Vec<String> {
    let mut redact_next = false;
    argv.into_iter()
        .map(|argument| {
            if redact_next {
                redact_next = false;
                return REDACTED.to_string();
            }
            redact_next = standalone_secret_flag(&argument);
            redact_text(&argument)
        })
        .collect()
}

fn standalone_secret_flag(argument: &str) -> bool {
    let normalized = argument
        .trim_start_matches('-')
        .replace('-', "_")
        .to_ascii_lowercase();
    [
        "api_key",
        "apikey",
        "token",
        "password",
        "secret",
        "credential",
        "authorization",
    ]
    .contains(&normalized.as_str())
}

fn sanitized_value(mut value: Value) -> Result<Value> {
    redact_value(&mut value, None);
    Ok(value)
}

fn redact_value(value: &mut Value, key: Option<&str>) {
    if key.is_some_and(secret_key) {
        *value = Value::String(REDACTED.to_string());
        return;
    }
    match value {
        Value::String(text) => *text = redact_text(text),
        Value::Array(items) => redact_array(items),
        Value::Object(object) => redact_object(object),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn redact_array(items: &mut Vec<Value>) {
    for item in items {
        redact_value(item, None);
    }
}

fn redact_object(object: &mut Map<String, Value>) {
    for (key, value) in object.iter_mut() {
        redact_value(value, Some(key));
    }
}

fn secret_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase();
    if normalized == "processstarttoken" {
        return false;
    }
    if normalized.ends_with("token") || normalized == "auth" {
        return true;
    }
    [
        "apikey",
        "accesstoken",
        "refreshtoken",
        "password",
        "secret",
        "credential",
        "authorization",
        "cookie",
        "privatekey",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn redact_text(text: &str) -> String {
    redaction_patterns()
        .iter()
        .fold(text.to_string(), |body, pattern| {
            pattern.replace_all(&body, REDACTED).into_owned()
        })
}

fn redaction_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            r"(?i)(?:^|\s)--(?:api[-_]?key|token|password|secret|credential|authorization)(?:=|\s+)\S+",
            r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}",
            r"(?i)(?:authorization|proxy-authorization)\s*[:=]\s*\S+(?:\s+\S+)?",
            r"(?i)(?:set-cookie|cookie)\s*[:=]\s*[^\r\n]+",
            r"\bsk-[A-Za-z0-9_-]{12,}\b",
            r"\bgh[pousr]_[A-Za-z0-9]{12,}\b",
            r"(?i)(?:api[-_]?key|access[-_]?token|token|password|secret)\s*[=:]\s*[^\s,;]+",
        ]
        .into_iter()
        .map(|pattern| Regex::new(pattern).expect("static redaction regex must compile"))
        .collect()
    })
}

fn strip_url_credentials(value: String) -> String {
    let Ok(mut url) = url::Url::parse(&value) else {
        return redact_text(&value);
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.to_string()
}

fn take_string(object: &mut Map<String, Value>, key: &str) -> Result<String> {
    object
        .remove(key)
        .and_then(|value| value.as_str().map(str::to_string))
        .with_context(|| format!("session event is missing {key}"))
}

fn empty_object() -> Value {
    Value::Object(Map::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freeform_authorization_headers_are_fully_redacted() {
        let redacted =
            redact_text("scan token=command-sentinel-secret Authorization: Basic header-secret");
        assert!(!redacted.contains("header-secret"), "{redacted}");
    }

    #[test]
    fn recursive_secret_keys_are_redacted_without_removing_safe_fields() {
        let mut value = serde_json::json!({
            "safe": "visible",
            "nested": {
                "apiKey": "key-sentinel",
                "items": [{"refresh_token": "token-sentinel"}]
            }
        });

        redact_value(&mut value, None);

        assert_eq!(value["safe"], "visible");
        assert_eq!(value["nested"]["apiKey"], REDACTED);
        assert_eq!(value["nested"]["items"][0]["refresh_token"], REDACTED);
    }
}
