use super::*;
mod workflow;

#[test]
fn bounded_answer_preserves_utf8_and_marks_the_byte_boundary() {
    let text = "α".repeat(40000);
    let answer = bounded_answer(&text);
    assert_eq!(answer.len(), 65536);
    assert!(text.starts_with(&answer));
}

#[test]
fn small_answer_is_unchanged() {
    assert_eq!(
        bounded_answer("Explanation\nwith evidence."),
        "Explanation\nwith evidence."
    );
}
