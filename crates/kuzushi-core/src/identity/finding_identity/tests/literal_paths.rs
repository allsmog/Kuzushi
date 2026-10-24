use super::*;

fn fingerprint(path: &str) -> String {
    stable_fingerprint_for_tool(
        "agentic",
        "owned-rule",
        path,
        "Owned claim",
        "Owned evidence",
    )
}

#[test]
fn literal_path_fingerprints_do_not_collapse_edge_whitespace() {
    let values = ["owned.rs", " owned.rs", "owned.rs "].map(fingerprint);
    assert_eq!(
        values
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3
    );
}

#[cfg(unix)]
#[test]
fn literal_path_fingerprints_keep_native_backslashes_distinct_from_separators() {
    assert_ne!(fingerprint("src/a.rs"), fingerprint("src\\a.rs"));
}

#[test]
fn literal_path_fingerprint_encoding_does_not_alias_a_real_prefix_filename() {
    assert_ne!(
        fingerprint(" odd.rs"),
        fingerprint("kuzushi-literal-path-v1:\" odd.rs\"")
    );
}

#[test]
fn literal_path_fix_keeps_the_existing_ordinary_fingerprint() {
    assert_eq!(
        stable_fingerprint_for_tool("agentic", "owned-shared-observation", "main.rs", "", ""),
        "fp3_25195d95ca371986f2ca869c55785ae285ffba0030d224eac9220829be7b2a0c"
    );
}
