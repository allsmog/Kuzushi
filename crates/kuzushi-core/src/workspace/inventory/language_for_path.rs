use std::path::Path;

pub(crate) fn language_for_path(path: &Path) -> Option<&'static str> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    language_kind_table()
        .iter()
        .find(|(extensions, _)| extensions.contains(&extension.as_str()))
        .map(|(_, language)| *language)
}

fn language_kind_table() -> &'static [(&'static [&'static str], &'static str)] {
    &[
        (&["js", "jsx", "mjs", "cjs"], "JavaScript"),
        (&["ts", "tsx"], "TypeScript"),
        (&["py"], "Python"),
        (&["go"], "Go"),
        (&["rs"], "Rust"),
        (&["java"], "Java"),
        (&["scala", "sc", "sbt"], "Scala"),
        (&["kt", "kts"], "Kotlin"),
        (&["cs"], "C#"),
        (&["rb"], "Ruby"),
        (&["php"], "PHP"),
        (&["c", "h"], "C"),
        (&["cc", "cpp", "cxx", "hh", "hpp", "hxx"], "C++"),
        (&["thrift"], "Thrift"),
    ]
}
