//! The context-generation document as drawn: readable plain lines, or a
//! question answer whose Markdown body is rendered as formatted text.
use super::*;
use crate::ui_view_models::context_generation::generation_lines;

/// The generation document as drawn, shared with scrolling so both agree on
/// its length. A question answer renders the model's Markdown; every other
/// view keeps readable plain lines.
pub(crate) fn generation_document_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    let answer = app
        .context_generation()
        .filter(|generation| generation.show_answer && !generation.show_brief_guidance);
    match answer {
        Some(generation) => answer_document_lines(generation, width),
        None => plain_document_lines(generation_lines(app, width)),
    }
}

fn plain_document_lines(lines: Vec<String>) -> Vec<Line<'static>> {
    lines
        .into_iter()
        .enumerate()
        .map(|(index, line)| {
            if index == 0 {
                Line::styled(line, theme::heading())
            } else {
                readable_line(&line)
            }
        })
        .collect()
}

fn answer_document_lines(
    generation: &crate::app::StudyContextGeneration,
    width: usize,
) -> Vec<Line<'static>> {
    let sections = crate::ui_view_models::context_generation::answer_sections(generation);
    let mut lines = plain_document_lines(wrapped(&sections.head, width));
    if let Some(markdown) = &sections.markdown {
        lines.extend(crate::renderer::shared::markdown::answer_markdown(
            markdown, width,
        ));
    }
    lines.extend(
        wrapped(&sections.tail, width)
            .iter()
            .map(|line| readable_line(line)),
    );
    lines
}

fn wrapped(lines: &[String], width: usize) -> Vec<String> {
    lines
        .iter()
        .flat_map(|line| {
            line.lines()
                .flat_map(|part| wrap_text(part, width.max(1)))
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answered(markdown: &str) -> crate::app::StudyContextGeneration {
        let answer = serde_json::from_value(serde_json::json!({
            "question": "Which endpoints are public?",
            "answer": markdown,
            "contextRef": {"modelId": "tm_1", "revisionId": "tmr_1", "sha256": "sha256:00"},
            "model": "anthropic:claude-haiku-5-5",
            "runId": "run-1",
            "sourceIdentity": "git:abc",
            "partial": false
        }))
        .expect("answer fixture");
        crate::app::StudyContextGeneration {
            generated_answer: Some(answer),
            show_answer: true,
            ..Default::default()
        }
    }

    fn text(lines: &[Line<'_>]) -> String {
        lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn answer_markdown_renders_without_raw_syntax() {
        let generation = answered("**Answer:** two routes.\n\n- `POST /login`\n- `GET /hello`");
        let rendered = text(&answer_document_lines(&generation, 80));

        assert!(rendered.contains("Answer: two routes."), "{rendered}");
        assert!(rendered.contains("POST /login"), "{rendered}");
        assert!(!rendered.contains("**"), "{rendered}");
        assert!(!rendered.contains('`'), "{rendered}");
        assert!(rendered.contains("Run: run-1"), "{rendered}");
    }
}
