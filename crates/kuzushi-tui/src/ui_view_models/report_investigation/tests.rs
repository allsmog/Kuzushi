use super::*;

#[test]
fn current_study_adds_no_source_currency_line() {
    assert!(source_currency_lines(true).is_empty());
}

#[test]
fn earlier_source_study_never_reads_as_current() {
    let lines = source_currency_lines(false);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].starts_with("Recorded on earlier source"));
    assert!(lines[0].contains("does not describe them"));
}
