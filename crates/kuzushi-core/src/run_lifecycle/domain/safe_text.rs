use serde::{Deserialize, Deserializer, Serialize};

pub const RUN_ITEM_REDACTION_POLICY_VERSION: u16 = 1;
const MAX_SAFE_TEXT_CHARS: usize = 6_000;
pub const MAX_PREVIEW_LINE_CHARS: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct SafeText(String);

impl SafeText {
    pub fn operator_visible(value: impl AsRef<str>) -> Self {
        let redacted = crate::session_transcript::redaction::redact_text(value.as_ref());
        Self(bound_text(&escape_controls(&redacted)))
    }

    pub fn preview_line(value: impl AsRef<str>) -> Self {
        let safe = Self::operator_visible(value);
        Self(bound_chars(safe.as_str(), MAX_PREVIEW_LINE_CHARS))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SafeText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let persisted = String::deserialize(deserializer)?;
        let safe = Self::operator_visible(&persisted);
        if safe.0 != persisted {
            return Err(serde::de::Error::custom(
                "persisted safe text violates policy",
            ));
        }
        Ok(safe)
    }
}

impl std::fmt::Display for SafeText {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn escape_controls(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| {
            if character.is_control() {
                character.escape_default().collect::<Vec<_>>()
            } else {
                vec![character]
            }
        })
        .collect()
}

fn bound_text(value: &str) -> String {
    bound_chars(value, MAX_SAFE_TEXT_CHARS)
}

fn bound_chars(value: &str, maximum: usize) -> String {
    if value.chars().count() <= maximum {
        return value.to_string();
    }
    let mut bounded = value.chars().take(maximum - 1).collect::<String>();
    bounded.push('…');
    bounded
}
