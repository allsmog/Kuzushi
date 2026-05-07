/// Escape a string for embedding in a Scala double-quoted literal. Mirrors
/// the cases joern actually trips on: backslash, double quote, newline.
pub fn escape_scala_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

/// `cpg.method.name(<fn>).caller.l` — methods that call `fn`.
pub fn callers_of(fn_name: &str) -> String {
    format!(
        "cpg.method.name(\"{}\").caller.dedup.l",
        escape_scala_string(fn_name)
    )
}

/// `cpg.method.name(<fn>).callee.l` — methods called by `fn`.
pub fn callees_of(fn_name: &str) -> String {
    format!(
        "cpg.method.name(\"{}\").callee.dedup.l",
        escape_scala_string(fn_name)
    )
}

/// Taint path query: methods reaching `sink` from `source` via joern's
/// `reachableByFlows`. Returns a list of paths; each path is a sequence
/// of CPG nodes from a source identifier to the sink call.
pub fn taint_paths(source_pattern: &str, sink_pattern: &str, max_paths: usize) -> String {
    format!(
        "def src = cpg.method.name(\"{src}\"); def snk = cpg.call.name(\"{snk}\"); snk.reachableByFlows(src.parameter).take({max}).l",
        src = escape_scala_string(source_pattern),
        snk = escape_scala_string(sink_pattern),
        max = max_paths
    )
}

/// Reaching-definition query for a variable at a specific (file, line).
/// Returns the definitions that flow into the identifier at that
/// location.
pub fn reaching_def(file: &str, line: u32, var: &str) -> String {
    format!(
        "cpg.identifier.name(\"{var}\").where(_.file.name(\"{file}\")).where(_.lineNumber({line})).reachingDefIn.dedup.l",
        var = escape_scala_string(var),
        file = escape_scala_string(file),
        line = line
    )
}

/// Locate `unsafe { ... }` regions via joern's Rust frontend. Joern's
/// Rust support tags unsafe blocks with a code prefix; we match by
/// regex against the call/block code. Constrained by file when
/// supplied, otherwise repo-wide.
pub fn unsafe_blocks(file: Option<&str>) -> String {
    let scope = match file {
        Some(f) => format!(".where(_.file.name(\"{}\"))", escape_scala_string(f)),
        None => String::new(),
    };
    format!(
        "cpg.all.collectAll[io.shiftleft.codepropertygraph.generated.nodes.Block]{scope}.code(\"(?s)unsafe\\\\s*\\\\{{.*\").dedup.l",
        scope = scope
    )
}

/// FFI-boundary query: locate `extern \"C\"` declarations (Rust + C),
/// `extern fn` (Rust), and JNI / dlsym calls. One Scala query, two
/// joern node types unioned.
pub fn ffi_boundaries() -> &'static str {
    r#"(cpg.method.where(_.fullName(".*extern.*")).map(m => Map("kind" -> "extern_fn", "name" -> m.fullName, "file" -> m.filename, "line" -> m.lineNumber.getOrElse(0))) ++ cpg.call.name("dlsym|dlopen|JNI_.*").map(c => Map("kind" -> "dynamic_load", "name" -> c.name, "file" -> c.file.name.headOption.getOrElse(""), "line" -> c.lineNumber.getOrElse(0)))).dedup.l"#
}

/// Locate the method enclosing a (file, line) coordinate.
pub fn method_at(file: &str, line: u32) -> String {
    format!(
        "cpg.method.where(_.file.name(\"{file}\")).where(_.lineNumber.lessThanOrEqual({line})).where(_.lineNumberEnd.greaterThanOrEqual({line})).head",
        file = escape_scala_string(file),
        line = line
    )
}

/// `cpg.method.fullName(...).numberOfLines` — small ergonomic check.
pub fn cpg_size_query() -> &'static str {
    "Map(\"nodes\" -> cpg.all.size, \"methods\" -> cpg.method.size, \"calls\" -> cpg.call.size)"
}

#[cfg(test)]
mod tests {
    use super::*;

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
