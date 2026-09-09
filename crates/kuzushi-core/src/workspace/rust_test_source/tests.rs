use super::*;

#[test]
fn preserves_offsets_unicode_and_production_on_the_same_line() {
    let text = "#[cfg(test)] mod tests { const EXAMPLE: &str = \"é界\"; } fn production() {}\n";
    let projected = surface_source("Rust", text);
    assert_eq!(projected.len(), text.len());
    assert_eq!(projected.find("fn production"), text.find("fn production"));
    assert!(!projected.contains("mod tests"));
    assert!(!projected.contains("#[cfg(test)]"));
    assert!(projected.ends_with('\n'));
}

#[test]
fn removes_all_attributes_of_excluded_function_without_steering_next_item() {
    let text = "#[cfg(test)]\n// comment\n#[inline]\nfn test_helper() {}\n#[tauri::command]\nfn production() {}";
    let projected = surface_source("Rust", text);
    assert!(!projected.contains("#[inline]"));
    assert!(!projected.contains("test_helper"));
    assert!(projected.contains("#[tauri::command]\nfn production"));
}

#[test]
fn inner_test_cfg_excludes_only_its_own_scope() {
    let text = "mod tests { #![cfg( test )] fn example() {} } fn production() {}";
    let projected = surface_source("Rust", text);
    assert!(!projected.contains("example"));
    assert!(projected.contains("production"));
    assert!(surface_source("Rust", "#![cfg(test)]\nfn main() {}\n")
        .trim()
        .is_empty());
}

#[test]
fn decoy_attributes_and_unknown_cfg_or_macros_do_not_hide_production() {
    for text in [
        "// #[cfg(test)]\nfn production() {}",
        "const EXAMPLE: &str = r#\"#[cfg(test)]\"#; fn production() {}",
        "#[cfg(any(test, feature = \"server\"))] fn production() {}",
        "#[cfg(all(test, feature = \"server\"))] fn conservative() {}",
        "#[cfg_attr(test, test)] fn production() {}",
        "#[other::test] fn production() {}",
        "#[test] struct InvalidAttributeTarget {}",
    ] {
        assert_eq!(surface_source("Rust", text), text);
    }
}

#[test]
fn malformed_scopes_and_other_languages_remain_visible() {
    let malformed = "#[cfg(test)] mod tests { fn incomplete(";
    assert_eq!(surface_source("Rust", malformed), malformed);
    let javascript = "const example = '#[cfg(test)]';";
    assert_eq!(surface_source("JavaScript", javascript), javascript);
}
