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

    /// One-line projection of possibly multi-line text: lines are trimmed and
    /// joined with " · " before escaping, so a condensed card never shows a
    /// literal `\n` where the producer meant a line break.
    pub fn condensed_line(value: impl AsRef<str>) -> Self {
        let joined = value
            .as_ref()
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join(" · ");
        Self::preview_line(joined)
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

#[cfg(test)]
mod condensed_line_tests {
    use super::SafeText;

    #[test]
    fn condensed_line_joins_multiline_text_without_escaped_newlines() {
        let condensed = SafeText::condensed_line(
            "[+] Triaged 13 of 13 findings (stage1 dropped 0)\n      tp=12  fp=1\n      cost=$3.58",
        );
        assert_eq!(
            condensed.as_str(),
            "[+] Triaged 13 of 13 findings (stage1 dropped 0) · tp=12  fp=1 · cost=$3.58"
        );
        assert!(!condensed.as_str().contains("\\n"));
    }

    #[test]
    fn condensed_line_still_escapes_other_control_characters() {
        let condensed = SafeText::condensed_line("alert\u{7} done");
        assert_eq!(condensed.as_str(), "alert\\u{7} done");
    }
}
