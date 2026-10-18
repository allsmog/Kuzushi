use super::*;

/// Typed path arrays preserve filenames; comma-separated shorthand trims entries.
pub(in crate::modules) fn path_list_input(
    input: &Value,
    keys: &[&str],
) -> Result<Option<Vec<String>>> {
    let Some(raw) = keys.iter().find_map(|key| input.get(*key)) else {
        return Ok(None);
    };
    let paths = super::super::options::coerce_string_list_option(raw.clone())?;
    Ok(Some(serde_json::from_value(paths)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn literal_paths_survive_arrays_and_aliases() {
        for key in ["paths", "includePaths", "include_paths"] {
            assert_eq!(
                path_list_input(&json!({key: [" app ", "note.rs ", " "]}), &[key]).unwrap(),
                Some(vec![" app ".into(), "note.rs ".into(), " ".into()])
            );
        }
    }

    #[test]
    fn comma_shorthand_keeps_compatibility_and_invalid_entries_fail() {
        assert_eq!(
            path_list_input(&json!({"paths": " app , docs "}), &["paths"]).unwrap(),
            Some(vec!["app".into(), "docs".into()])
        );
        for input in [
            json!({"paths": [""]}),
            json!({"paths": [1]}),
            json!({"paths": false}),
        ] {
            assert!(path_list_input(&input, &["paths"]).is_err());
        }
        assert_eq!(path_list_input(&json!({}), &["paths"]).unwrap(), None);
    }
}
