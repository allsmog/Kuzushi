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

pub fn callers_of(fn_name: &str) -> String {
    format!(
        "cpg.method.name(\"{}\").caller.dedup.l",
        escape_scala_string(fn_name)
    )
}

pub fn callees_of(fn_name: &str) -> String {
    format!(
        "cpg.method.name(\"{}\").callee.dedup.l",
        escape_scala_string(fn_name)
    )
}

/// Hard ceiling on `maxCallDepth`. Joern's interprocedural dataflow
/// is exponential in call-graph depth on large CPGs (a 187 MB postgres
/// CPG with depth 32 already pushes the JVM into long pauses), so we
/// clamp here regardless of what the caller asked for.
pub const TAINT_PATHS_MAX_CALL_DEPTH_CEILING: u32 = 32;

/// Default `maxCallDepth` when the caller didn't supply one. Roughly
/// matches joern's own implicit cutoff while staying explicit so the
/// query string carries the intent.
pub const TAINT_PATHS_DEFAULT_CALL_DEPTH: u32 = 12;

pub fn taint_paths(
    source_pattern: &str,
    sink_pattern: &str,
    max_paths: usize,
    max_call_depth: Option<u32>,
) -> String {
    // Source nodes union: matches against both call expressions
    // (e.g. postgres `PG_GETARG_TEXT_PP(0)` lands as a call in the
    // CPG, not a method) and method parameters (the original
    // request/argv-style sources). Without the call branch, regex
    // sources like `PG_GETARG_TEXT_PP` against
    // `cpg.method.name(...).parameter` matched no nodes and
    // `reachableByFlows` silently returned an empty list — which is
    // why every postgres CWE-78 / CWE-94 / CWE-426 hunt landed at
    // "candidate, no joern flow" in spite of the structural pass
    // surfacing real call sites.
    //
    // We also tag both branches so the response carries a node count
    // per traversal; downstream callers can distinguish "the source
    // pattern matched nothing" from "the source matched but no flow
    // reaches the sink".
    //
    // The `maxCallDepth` knob lets the agent crank interprocedural
    // depth on retry when the first call returned `flowCount=0` while
    // sources and sinks both resolved (a strong signal that joern
    // simply gave up before connecting the long postgres-style chain).
    let depth = max_call_depth
        .unwrap_or(TAINT_PATHS_DEFAULT_CALL_DEPTH)
        .min(TAINT_PATHS_MAX_CALL_DEPTH_CEILING);
    // The `implicit val engineContext` overrides joern's default
    // EngineContext for the rest of the query so `reachableByFlows`
    // picks up our `maxCallDepth`. Joern pre-imports the queryengine
    // package in its Scala REPL but we fully-qualify here so the
    // query is robust to minor REPL-import drift across versions.
    format!(
        "implicit val engineContext: io.joern.dataflowengineoss.queryengine.EngineContext = \
            io.joern.dataflowengineoss.queryengine.EngineContext(\
                config = io.joern.dataflowengineoss.queryengine.EngineConfig(maxCallDepth = {depth}) \
            ); \
         def srcCalls = cpg.call.name(\"{src}\"); \
         def srcParams = cpg.method.name(\"{src}\").parameter; \
         def srcs = (srcCalls.cast[io.shiftleft.codepropertygraph.generated.nodes.CfgNode] ++ srcParams.cast[io.shiftleft.codepropertygraph.generated.nodes.CfgNode]).dedup; \
         def snk = cpg.call.name(\"{snk}\"); \
         val sourceCounts = Map(\"calls\" -> srcCalls.size, \"methodParams\" -> srcParams.size); \
         val sinkCount = snk.size; \
         val flows = snk.reachableByFlows(srcs).take({max}).l; \
         Map(\"sourceCounts\" -> sourceCounts, \"sinkCount\" -> sinkCount, \"maxCallDepth\" -> {depth}, \"flowCount\" -> flows.size, \"flows\" -> flows)",
        src = escape_scala_string(source_pattern),
        snk = escape_scala_string(sink_pattern),
        max = max_paths,
        depth = depth,
    )
}

pub fn reaching_def(file: &str, line: u32, var: &str) -> String {
    format!(
        "cpg.identifier.name(\"{var}\").where(_.file.name(\"{file}\")).where(_.lineNumber({line})).reachingDefIn.dedup.l",
        var = escape_scala_string(var),
        file = escape_scala_string(file),
        line = line
    )
}

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

pub fn ffi_boundaries() -> &'static str {
    r#"(cpg.method.where(_.fullName(".*extern.*")).map(m => Map("kind" -> "extern_fn", "name" -> m.fullName, "file" -> m.filename, "line" -> m.lineNumber.getOrElse(0))) ++ cpg.call.name("dlsym|dlopen|JNI_.*").map(c => Map("kind" -> "dynamic_load", "name" -> c.name, "file" -> c.file.name.headOption.getOrElse(""), "line" -> c.lineNumber.getOrElse(0)))).dedup.l"#
}

pub fn method_at(file: &str, line: u32) -> String {
    format!(
        "cpg.method.where(_.file.name(\"{file}\")).where(_.lineNumber.lessThanOrEqual({line})).where(_.lineNumberEnd.greaterThanOrEqual({line})).head",
        file = escape_scala_string(file),
        line = line
    )
}

pub fn cpg_size_query() -> &'static str {
    "Map(\"nodes\" -> cpg.all.size, \"methods\" -> cpg.method.size, \"calls\" -> cpg.call.size)"
}
