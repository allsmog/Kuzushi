use super::reported_path;

#[cfg(unix)]
#[test]
fn file_uri_reads_back_the_encoded_name_the_encoder_wrote() {
    // The exact string clangd/protocol.rs::file_uri produces for this path,
    // asserted by that crate's own encoder test.
    let path = reported_path("file:///tmp/a%20b%23%25%C3%A9.c");

    assert_eq!(path.as_deref(), Some("/tmp/a b#%é.c"));
}

#[test]
fn relative_reference_decodes_and_stays_relative() {
    let path = reported_path("src/caf%C3%A9/My%20Query.rs");

    assert_eq!(path.as_deref(), Some("src/café/My Query.rs"));
}

#[test]
fn escaped_separator_decodes_to_a_separator() {
    // No path segment on a supported platform can hold `/`, so an escaped one
    // is only ever a separator its producer escaped.
    assert_eq!(reported_path("src%2Fio.c").as_deref(), Some("src/io.c"));
}

#[test]
fn unescaped_name_reads_back_unchanged() {
    assert_eq!(reported_path("src/io.c").as_deref(), Some("src/io.c"));
    assert_eq!(
        reported_path("file:///repo/a.c").as_deref(),
        Some("/repo/a.c")
    );
}

#[test]
fn lone_percent_stays_literal() {
    // The lenient reading of a non-conformant producer's output: the location
    // is still reported rather than dropped.
    assert_eq!(
        reported_path("src/100%done.c").as_deref(),
        Some("src/100%done.c")
    );
}

#[test]
fn non_file_scheme_is_an_identifier_and_is_not_decoded() {
    let uri = "https://example.test/scan?path=a%2Fb";

    assert_eq!(reported_path(uri).as_deref(), Some(uri));
}

#[test]
fn windows_drive_reference_is_decoded_rather_than_read_as_a_scheme() {
    assert_eq!(
        reported_path("C:/work%20dir/a.c").as_deref(),
        Some("C:/work dir/a.c")
    );
}

#[test]
fn non_local_file_host_names_no_local_path() {
    assert_eq!(reported_path("file://build01/share/a.c"), None);
}

#[test]
fn non_utf8_escape_sequence_is_skipped_rather_than_replaced() {
    assert_eq!(reported_path("src/%FF.c"), None);
}

#[test]
fn empty_reference_names_nothing() {
    assert_eq!(reported_path(""), None);
    assert_eq!(reported_path("file://"), None);
}
