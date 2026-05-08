#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn escapes_backslash_and_quotes() {
        assert_eq!(escape_scala_string(r#"a"b\c"#), r#"a\"b\\c"#);
    }

    #[test]
    fn callers_of_quotes_function_name() {
        let q = callers_of("recv_msg");
        assert!(q.contains("\"recv_msg\""));
        assert!(q.contains("caller"));
    }

    #[test]
    fn callers_of_resists_quote_injection() {
        let q = callers_of(r#"foo"; cpg.method.name("bar").l;//"#);
        // The injected closing quote and following code must end up
        // escaped inside the string literal — never as live Scala.
        assert!(q.contains(r#"foo\""#));
        assert!(!q.contains("); cpg.method.name(\"bar\")"));
    }

    #[test]
    fn taint_paths_includes_max_count() {
        let q = taint_paths("argv", "system", 50);
        assert!(q.contains("take(50)"));
        assert!(q.contains("\"argv\""));
        assert!(q.contains("\"system\""));
    }

    #[test]
    fn reaching_def_quotes_var_file_and_line() {
        let q = reaching_def("/r/a.c", 42, "buf");
        assert!(q.contains("\"buf\""));
        assert!(q.contains("\"/r/a.c\""));
        assert!(q.contains("lineNumber(42)"));
    }

    #[test]
    fn unsafe_blocks_repo_wide_has_no_file_filter() {
        let q = unsafe_blocks(None);
        assert!(q.contains("Block"));
        assert!(q.contains("unsafe"));
        // No file filter when scope is None.
        assert!(!q.contains(".where(_.file.name"));
    }

    #[test]
    fn unsafe_blocks_constrained_to_file_includes_filter() {
        let q = unsafe_blocks(Some("/r/lib.rs"));
        assert!(q.contains(".where(_.file.name(\"/r/lib.rs\"))"));
    }

    #[test]
    fn ffi_boundaries_unions_extern_and_dynamic_load() {
        let q = ffi_boundaries();
        assert!(q.contains("extern"));
        assert!(q.contains("dlsym"));
        assert!(q.contains("JNI_"));
    }

    #[test]
    fn method_at_filters_by_file_and_line_window() {
        let q = method_at("/r/a.c", 100);
        assert!(q.contains("\"/r/a.c\""));
        assert!(q.contains("lessThanOrEqual(100)"));
        assert!(q.contains("greaterThanOrEqual(100)"));
    }

    #[test]
    fn reaching_def_resists_quote_injection_in_var_name() {
        let q = reaching_def("/r/a.c", 1, r#"buf"; cpg.method.name("evil").l;//"#);
        assert!(q.contains(r#"buf\""#));
        assert!(!q.contains("cpg.method.name(\"evil\")"));
    }
}
