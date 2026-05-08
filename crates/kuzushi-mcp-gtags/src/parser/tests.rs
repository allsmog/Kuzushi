#[cfg(test)]
mod tests {
    use super::super::*;

    /// Captured `global -x` output for a hypothetical lookup of
    /// `recv_msg`. Three records, the third with a snippet containing
    /// embedded whitespace and tabs.
    const FIXTURE: &str = "\
recv_msg            42 src/net.c                int recv_msg(int fd, struct msg *m) {
recv_msg           107 src/proto.c              extern int recv_msg(int, struct msg *);
__recv_msg_hook      3 vendor/inst.h            #define __recv_msg_hook(...) /* ... */\t/* annotated */
";

    #[test]
    fn parses_three_records_from_fixture() {
        let records = parse_global_x(FIXTURE);
        assert_eq!(records.len(), 3);

        assert_eq!(records[0].symbol, "recv_msg");
        assert_eq!(records[0].line, 42);
        assert_eq!(records[0].file, PathBuf::from("src/net.c"));
        assert!(records[0].snippet.starts_with("int recv_msg"));

        assert_eq!(records[2].symbol, "__recv_msg_hook");
        assert_eq!(records[2].line, 3);
        assert!(records[2].snippet.contains("#define __recv_msg_hook"));
        assert!(records[2].snippet.contains("/* annotated */"));
    }

    #[test]
    fn ignores_blank_and_garbled_lines() {
        let records = parse_global_x("\n\n\nfoo\n");
        assert!(
            records.is_empty(),
            "lines without line+file fields are skipped"
        );
    }

    #[test]
    fn line_with_no_snippet_still_parses() {
        let line = "main 1 src/main.c";
        let r = parse_global_x_line(line).unwrap();
        assert_eq!(r.symbol, "main");
        assert_eq!(r.line, 1);
        assert_eq!(r.file, PathBuf::from("src/main.c"));
        assert_eq!(r.snippet, "");
    }

    #[test]
    fn records_to_symbols_resolves_relative_paths() {
        let records = parse_global_x(FIXTURE);
        let syms = records_to_symbols(records, std::path::Path::new("/repo"));
        assert_eq!(
            syms[0].location.start.file,
            PathBuf::from("/repo/src/net.c")
        );
        assert_eq!(syms[0].location.start.line, 42);
    }
}
