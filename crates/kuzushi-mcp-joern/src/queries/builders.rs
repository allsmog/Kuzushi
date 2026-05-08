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

pub fn taint_paths(source_pattern: &str, sink_pattern: &str, max_paths: usize) -> String {
    format!(
        "def src = cpg.method.name(\"{src}\"); def snk = cpg.call.name(\"{snk}\"); snk.reachableByFlows(src.parameter).take({max}).l",
        src = escape_scala_string(source_pattern),
        snk = escape_scala_string(sink_pattern),
        max = max_paths
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
