use super::{escape_controls, SafeText, MAX_SAFE_TEXT_CHARS};

pub(super) fn lines(value: &str) -> Vec<SafeText> {
    crate::session_transcript::redaction::redact_text(value)
        .split('\n')
        .flat_map(safe_line)
        .collect()
}

fn safe_line(value: &str) -> Vec<SafeText> {
    let characters = escape_controls(value).chars().collect::<Vec<_>>();
    if characters.is_empty() {
        return vec![SafeText(String::new())];
    }
    characters
        .chunks(MAX_SAFE_TEXT_CHARS)
        .map(|chunk| SafeText(chunk.iter().collect()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_retains_whitespace_unicode_and_every_character_of_long_lines() {
        let text = format!("  owned café\n\n{}\n", "資料".repeat(7000));
        let safe = lines(&text);
        assert_eq!(safe[0].as_str(), "  owned café");
        assert_eq!(safe[1].as_str(), "");
        assert_eq!(
            safe[2..safe.len() - 1]
                .iter()
                .map(SafeText::as_str)
                .collect::<String>(),
            "資料".repeat(7000)
        );
        assert_eq!(safe.last().unwrap().as_str(), "");
        assert!(safe
            .iter()
            .all(|line| line.as_str().chars().count() <= MAX_SAFE_TEXT_CHARS));
    }

    #[test]
    fn document_uses_existing_secret_redaction_and_escapes_controls() {
        let source = "OPENAI_API_KEY=sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\u{1b}[31mowned\ttext";
        let display = lines(source)
            .iter()
            .map(SafeText::as_str)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!display.contains("sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        assert!(!display.contains('\u{1b}') && !display.contains('\t'));
        assert!(display.contains("owned") && display.contains("text"));
    }
}
