use super::*;

fn mixed_projects(root: &std::path::Path) -> Vec<(String, kuzushi_cpg::Project)> {
    std::fs::write(
        root.join("shared.h"),
        "static inline int shared(int x) { return x; }\n",
    )
    .unwrap();
    std::fs::write(root.join("main.c"), "#include \"shared.h\"\n").unwrap();
    std::fs::write(root.join("main.cpp"), "#include \"shared.h\"\n").unwrap();
    ["c", "cpp"]
        .into_iter()
        .map(|language| {
            (
                language.to_string(),
                kuzushi_cpg::ensure_project(root, language).unwrap().0,
            )
        })
        .collect()
}

#[test]
fn graph_scoped_selectors_resolve_identical_shared_header_methods() {
    let root = tempfile::tempdir().unwrap();
    let projects = mixed_projects(root.path());
    assert!(ensure_unique_function(&projects, "shared").is_err());
    let definitions = method_results(&projects, |project| {
        Ok(queries::methods_named(project, "shared"))
    })
    .unwrap();
    assert_eq!(definitions.len(), 2);
    assert_ne!(definitions[0]["selector"], definitions[1]["selector"]);
    for definition in definitions {
        let (selected, name) =
            method_scope(&projects, definition["selector"].as_str().unwrap()).unwrap();
        assert_eq!(selected.len(), 1);
        ensure_unique_function(selected, name).unwrap();
        assert_eq!(queries::methods_named(&selected[0].1, name).len(), 1);
    }
    assert!(method_scope(&projects, "absent:method:deadbeef").is_err());
}

#[test]
fn absent_files_do_not_produce_authoritative_empty_evidence() {
    let root = tempfile::tempdir().unwrap();
    let projects = mixed_projects(root.path());
    assert!(ensure_unique_file(&projects, "missing.c")
        .unwrap_err()
        .to_string()
        .contains("membership unavailable"));
    assert!(ensure_unique_file(&projects, "shared.h").is_err());
    ensure_unique_file(&projects, "main.c").unwrap();
}
