use super::*;

fn text(source: &str, width: usize) -> String {
    answer_markdown(source, width)
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn headings_and_nested_inline_emphasis_keep_styles_across_wrapping() {
    let lines = answer_markdown(
        "## Boundary\n\n**strong and *nested italic*** with ~~old~~ and `code`.",
        18,
    );
    assert_eq!(lines[0].to_string(), "Boundary");
    assert!(lines[0].spans[0]
        .style
        .add_modifier
        .contains(Modifier::BOLD));
    let nested = lines
        .iter()
        .flat_map(|line| &line.spans)
        .find(|span| span.content.contains("nested"))
        .unwrap();
    assert!(nested
        .style
        .add_modifier
        .contains(Modifier::BOLD | Modifier::ITALIC));
    assert!(lines
        .iter()
        .flat_map(|line| &line.spans)
        .any(|span| span.style.add_modifier.contains(Modifier::CROSSED_OUT)));
    assert!(lines.iter().all(|line| line.width() <= 18));
}

#[test]
fn fenced_and_indented_code_keep_whitespace_blank_lines_and_literal_markup() {
    let source =
        "```rust\nfn run() {\n    **literal**\n\n\t東京();\n}\n```\n\n    let indented = true;";
    let output = text(source, 40);
    assert!(output.contains("Code · rust"), "{output}");
    assert!(
        output.contains("│     **literal**\n│ \n│     東京();"),
        "{output}"
    );
    assert!(output.contains("│ let indented = true;"), "{output}");
}

#[test]
fn nested_lists_preserve_numbers_tasks_and_quote_hierarchy() {
    let output = text(
        "7. First\n   - [x] Done\n   - [ ] Waiting\n8. Second\n\n> Quote with **evidence**",
        40,
    );
    for expected in [
        "7. First",
        "   • [x] Done",
        "   • [ ] Waiting",
        "8. Second",
        "│ Quote with evidence",
    ] {
        assert!(output.contains(expected), "missing {expected}: {output}");
    }
}

#[test]
fn links_images_and_footnotes_keep_labels_destinations_and_definitions() {
    let source = "[Source](https://example.test/source.rs#L42) and ![DFD](./diagram.svg). Proof[^a].\n\n[^a]: Unverified hypothesis.";
    let output = text(source, 120);
    for expected in [
        "Source (https://example.test/source.rs#L42)",
        "Image: DFD (./diagram.svg)",
        "Proof[a]",
        "[a] Unverified hypothesis",
    ] {
        assert!(output.contains(expected), "missing {expected}: {output}");
    }
}

#[test]
fn table_grid_and_narrow_records_keep_all_cell_values_and_inline_styles() {
    let source = "| Check | Evidence | Status |\n| :--- | :---: | ---: |\n| **Permission** | Source not verified | Open |\n| Scope | Selected target only | Held |";
    let wide = text(source, 80);
    assert!(wide.contains('┼') && wide.contains('│'), "{wide}");
    let narrow = text(source, 24);
    for expected in [
        "Check: Permission",
        "Evidence: Source not",
        "verified",
        "Status: Open",
        "Check: Scope",
        "Selected",
        "target only",
        "Status: Held",
    ] {
        assert!(narrow.contains(expected), "missing {expected}: {narrow}");
    }
    for width in [18, 24, 40, 80] {
        assert!(answer_markdown(source, width)
            .iter()
            .all(|line| line.width() <= width));
    }
}

#[test]
fn unicode_graphemes_and_long_links_remain_complete_when_wrapped() {
    let source = "東京 👩‍💻 e\u{301} [link](https://example.test/abcdefghijklmnopqrstuvwxyz)";
    let output = text(source, 18);
    assert!(output.contains("東京 👩‍💻 e\u{301}"), "{output}");
    assert!(
        output
            .replace('\n', "")
            .contains("https://example.test/abcdefghijklmnopqrstuvwxyz"),
        "{output}"
    );
    assert!(answer_markdown(source, 18)
        .iter()
        .all(|line| line.width() <= 18));
}

#[test]
fn incomplete_fences_and_terminal_control_text_render_as_inert_content() {
    let source = "```text\n    unfinished **code**\n\u{1b}]52;c;payload\u{7}";
    let output = text(source, 60);
    assert!(output.contains("    unfinished **code**"), "{output}");
    assert!(output.contains("payload"), "{output}");
    assert!(!output.contains('\u{1b}') && !output.contains('\u{7}'));
    assert!(text("<script>literal()</script>", 80).contains("<script>literal()</script>"));
}

#[test]
fn wrapped_code_marks_continuations_without_removing_source_characters() {
    let line = "    first_argument + second_argument + 東京";
    let output = text(&format!("```rust\n{line}\n```"), 18);
    assert!(output.contains("↪ "), "{output}");
    let recovered: String = output
        .lines()
        .filter_map(|line| line.strip_prefix("│ ").or_else(|| line.strip_prefix("↪ ")))
        .collect();
    assert_eq!(recovered, line);
}

#[test]
fn deeply_nested_content_remains_readable_without_recursive_rendering() {
    let source = format!("{}last evidence", "> ".repeat(500));
    let output = text(&source, 40);
    assert!(output.contains("last evidence"), "{output}");
    assert!(
        output.starts_with("> > >"),
        "excessive nesting should retain literal content"
    );
}
