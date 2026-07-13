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
    fn definitions_are_typed_and_resist_quote_injection() {
        let q = definitions(r#"foo"; cpg.all.l;//"#);
        assert!(q.contains("nameExact"));
        assert!(q.contains("\"location\""));
        assert!(q.contains(r#"foo\""#));
        assert!(!q.contains("; cpg.all.l;//\").l"));
    }

    #[test]
    fn taint_paths_includes_max_count() {
        let q = taint_paths("argv", "system", 50, None);
        assert!(q.contains("take(50)"));
        assert!(q.contains("\"argv\""));
        assert!(q.contains("\"system\""));
    }

    #[test]
    fn taint_paths_unions_call_and_method_parameter_sources() {
        // The single most important regression: the prior builder
        // treated `source` as a method-name regex only, so call-style
        // sources (postgres `PG_GETARG_TEXT_PP`, JS `req.query`)
        // matched no nodes and reachableByFlows silently returned an
        // empty list. The new builder must union both kinds and
        // surface a per-traversal node count so the agent can tell
        // "source matched nothing" from "source matched but no flow
        // reaches the sink".
        let q = taint_paths("PG_GETARG_TEXT_PP", "snprintf", 25, None);
        assert!(
            q.contains("cpg.call.name(\"PG_GETARG_TEXT_PP\")"),
            "expected call-name source traversal in: {q}"
        );
        assert!(
            q.contains("cpg.method.name(\"PG_GETARG_TEXT_PP\").parameter"),
            "expected method-parameter source traversal in: {q}"
        );
        assert!(
            q.contains("reachableByFlows(srcs)"),
            "expected the unioned `srcs` traversal to be the reachableByFlows input in: {q}"
        );
        // Output envelope must report counts so the agent can
        // distinguish "no source" from "no flow".
        assert!(q.contains("sourceCounts"));
        assert!(q.contains("sinkCount"));
        assert!(q.contains("flowCount"));
    }

    #[test]
    fn taint_paths_emits_default_call_depth_when_none_supplied() {
        let q = taint_paths("argv", "system", 10, None);
        // The default call depth must show up both in the EngineConfig
        // override and in the response envelope so the agent can see
        // what depth produced the result.
        assert!(
            q.contains(&format!(
                "maxCallDepth = {}",
                TAINT_PATHS_DEFAULT_CALL_DEPTH
            )),
            "expected default maxCallDepth in EngineConfig in: {q}"
        );
        assert!(q.contains("\"maxCallDepth\""));
    }

    #[test]
    fn taint_paths_threads_caller_supplied_depth() {
        let q = taint_paths("argv", "system", 10, Some(24));
        assert!(
            q.contains("maxCallDepth = 24"),
            "expected maxCallDepth = 24 in EngineConfig in: {q}"
        );
        // Implicit val is mandatory so reachableByFlows picks up the
        // override; without it joern silently uses its default.
        assert!(
            q.contains("implicit val engineContext"),
            "expected implicit EngineContext binding in: {q}"
        );
    }

    #[test]
    fn taint_paths_clamps_depth_to_ceiling() {
        // A 50-deep request must clamp to the 32 ceiling — joern's
        // dataflow engine is exponential in depth on large CPGs and
        // values past 32 routinely trigger JVM pauses we'd rather
        // surface as "no path at depth 32" than as a tool timeout.
        let q = taint_paths("argv", "system", 10, Some(50));
        assert!(
            q.contains(&format!(
                "maxCallDepth = {}",
                TAINT_PATHS_MAX_CALL_DEPTH_CEILING
            )),
            "expected clamped maxCallDepth = ceiling in: {q}"
        );
        assert!(
            !q.contains("maxCallDepth = 50"),
            "must not pass uncapped depth to joern in: {q}"
        );
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
