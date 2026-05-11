use super::*;

pub(crate) fn taint_iris_next_line_matches(line_lower: &str, pattern: &str) -> bool {
    let pattern_lower = pattern.to_ascii_lowercase();
    if pattern_starts_with_identifier_char(&pattern_lower) {
        if line_contains_with_identifier_word_boundary(line_lower, &pattern_lower) {
            return true;
        }
    } else if line_lower.contains(&pattern_lower) {
        return true;
    }
    taint_iris_next_alias_match(line_lower, pattern_lower.as_str())
}

fn line_contains_with_identifier_word_boundary(line: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }

    let line_bytes = line.as_bytes();
    let pattern_bytes = pattern.as_bytes();
    let mut index = 0;
    while index + pattern_bytes.len() <= line_bytes.len() {
        if &line_bytes[index..index + pattern_bytes.len()] == pattern_bytes
            && (index == 0 || !is_identifier_byte(line_bytes[index - 1]))
        {
            return true;
        }
        index += 1;
    }
    false
}

fn pattern_starts_with_identifier_char(pattern: &str) -> bool {
    pattern
        .as_bytes()
        .first()
        .is_some_and(|byte| is_identifier_byte(*byte))
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn taint_iris_next_alias_match(line_lower: &str, pattern: &str) -> bool {
    match pattern {
        "query parameter" | "route parameter" => {
            line_lower.contains("req.query")
                || line_lower.contains("request.args")
                || line_lower.contains("params")
        }
        "request body" => line_lower.contains("req.body") || line_lower.contains("request.body"),
        "request path" => line_lower.contains("req.path") || line_lower.contains("request.path"),
        "webhook url" | "callback url" | "request url" => {
            line_lower.contains("req.query.url")
                || line_lower.contains("request.url")
                || line_lower.contains("url")
        }
        "prepared statement" | "parameterized query" | "bind parameter" => {
            line_lower.contains("$1") || line_lower.contains("?") || line_lower.contains("bind")
        }
        _ => false,
    }
}

pub(crate) fn taint_iris_next_kind_for_role(role: &str) -> &'static str {
    match role {
        "source" => "external-return-source",
        "sink" => "external-arg-sink",
        "sanitizer" => "sanitizer",
        _ => "control-context",
    }
}

pub(crate) fn build_taint_iris_next_linked_stories(
    candidates: &[TaintIrisNextCandidate],
) -> Vec<TaintIrisNextLinkedStory> {
    let mut stories = Vec::new();
    for source in candidates
        .iter()
        .filter(|candidate| candidate.role == "source")
    {
        for sink in candidates
            .iter()
            .filter(|candidate| candidate.role == "sink" && candidate.cwe == source.cwe)
        {
            if sink.file_path != source.file_path {
                continue;
            }
            let distance = sink.line.abs_diff(source.line);
            if distance > 80 {
                continue;
            }
            let shared_tokens = shared_taint_iris_next_tokens(&source.snippet, &sink.snippet);
            stories.push(TaintIrisNextLinkedStory {
                id: format!("linked-{}-{}", source.id, sink.id),
                cwe: source.cwe.clone(),
                taint_class: source.taint_class.clone(),
                track: source.track.clone(),
                evidence_level: "linked".to_string(),
                file_path: source.file_path.clone(),
                language: source.language.clone(),
                source_candidate_id: source.id.clone(),
                sink_candidate_id: sink.id.clone(),
                source_line: source.line,
                sink_line: sink.line,
                shared_tokens: shared_tokens.clone(),
                rationale: format!(
                    "{} source at line {} is near {} sink at line {}{}",
                    source.catalog_signal,
                    source.line,
                    sink.catalog_signal,
                    sink.line,
                    if shared_tokens.is_empty() {
                        String::new()
                    } else {
                        format!(" with shared tokens {}", shared_tokens.join(", "))
                    }
                ),
            });
        }
    }
    stories.sort_by(|left, right| {
        cwe_priority(&right.cwe)
            .cmp(&cwe_priority(&left.cwe))
            .then_with(|| left.file_path.cmp(&right.file_path))
            .then_with(|| left.sink_line.cmp(&right.sink_line))
    });
    stories
}

pub(crate) fn shared_taint_iris_next_tokens(left: &str, right: &str) -> Vec<String> {
    let left_tokens = identifier_tokens(left);
    let right_tokens = identifier_tokens(right);
    left_tokens
        .intersection(&right_tokens)
        .filter(|token| token.len() > 2)
        .take(8)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_matches_enforces_identifier_word_boundary() {
        assert!(taint_iris_next_line_matches(
            "    sprintf(buf, \"hi %s\", arg);",
            "sprintf("
        ));
        assert!(!taint_iris_next_line_matches(
            "    psprintf(\"%u\", stat.blkno);",
            "sprintf("
        ));
        assert!(taint_iris_next_line_matches(
            "    strcpy(dest, src);",
            "strcpy("
        ));
        assert!(!taint_iris_next_line_matches(
            "    pg_strcpy(dest, src);",
            "strcpy("
        ));
        assert!(taint_iris_next_line_matches(
            "    strcat(dest, src);",
            "strcat("
        ));
        assert!(!taint_iris_next_line_matches(
            "    pg_strcat(dest, src);",
            "strcat("
        ));
        assert!(taint_iris_next_line_matches(
            "    text *t = pg_getarg_text_pp(0);",
            "PG_GETARG_TEXT_PP"
        ));
        assert!(taint_iris_next_line_matches(
            "    const x = req.query.foo;",
            "req.query"
        ));
    }
}
