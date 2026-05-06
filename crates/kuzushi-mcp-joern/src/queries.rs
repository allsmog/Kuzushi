//! Scala-query templates passed to `joern --server`.
//!
//! These are deliberately small and quoted-arg-safe — joern's REST endpoint
//! takes a single Scala expression as a string parameter. We escape user
//! input that lands inside Scala string literals to avoid trivial injection
//! into the query.

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

/// Taint path query: methods reaching `sink` from `source`. The `.flows.l`
/// produces dataflow paths. Currently unused by the wired tools (the
/// `joern.taint_paths` MCP tool is a stub) but exercised by tests and
/// retained as stable, doc-tested infrastructure.
#[allow(dead_code)]
pub fn taint_paths(source_pattern: &str, sink_pattern: &str, max_paths: usize) -> String {
    format!(
        "def src = cpg.method.name(\"{src}\"); def snk = cpg.call.name(\"{snk}\"); snk.reachableByFlows(src.parameter).take({max}).l",
        src = escape_scala_string(source_pattern),
        snk = escape_scala_string(sink_pattern),
        max = max_paths
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
}
