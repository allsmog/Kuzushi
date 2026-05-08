#[cfg(test)]
mod tests {
    use super::super::*;
    use std::fs;
    use tempfile::tempdir;

    fn rg_available() -> bool {
        std::process::Command::new("rg")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[test]
    fn read_source_tool_round_trips_via_toolbox() {
        let tmp = tempdir().unwrap();
        fs::write(tmp.path().join("a.rs"), "fn main() {}\n").unwrap();
        let mut tb = code_nav_toolbox(CodeNavConfig::new(tmp.path()));

        let call = ToolCall {
            name: "read_source".to_string(),
            input: json!({ "file": "a.rs" }),
            call_id: "c1".to_string(),
        };
        let result = crate::runtime::ToolCallHandler::run(&mut tb, &call).unwrap();
        assert!(!result.is_error, "{result:?}");
        let contents = result.output["contents"].as_str().unwrap();
        assert!(contents.contains("fn main"));
    }

    #[test]
    fn unknown_tool_in_box_returns_error_result() {
        let tmp = tempdir().unwrap();
        let mut tb = code_nav_toolbox(CodeNavConfig::new(tmp.path()));
        let call = ToolCall {
            name: "made_up_tool".to_string(),
            input: json!({}),
            call_id: "c1".to_string(),
        };
        let result = crate::runtime::ToolCallHandler::run(&mut tb, &call).unwrap();
        assert!(result.is_error);
    }

    #[test]
    fn find_references_tool_round_trips_via_toolbox() {
        if !rg_available() {
            eprintln!("rg not on PATH; skipping");
            return;
        }
        let tmp = tempdir().unwrap();
        fs::write(
            tmp.path().join("a.rs"),
            "fn target() {}\nfn other() { target() }\n",
        )
        .unwrap();
        let mut tb = code_nav_toolbox(CodeNavConfig::new(tmp.path()));
        let call = ToolCall {
            name: "find_references".to_string(),
            input: json!({ "symbol": "target" }),
            call_id: "c1".to_string(),
        };
        let result = crate::runtime::ToolCallHandler::run(&mut tb, &call).unwrap();
        assert!(!result.is_error, "{result:?}");
        let hits = result.output["hits"].as_array().unwrap();
        assert!(hits.len() >= 2);
    }

    #[test]
    fn malformed_input_is_error_not_panic() {
        let tmp = tempdir().unwrap();
        let mut tb = code_nav_toolbox(CodeNavConfig::new(tmp.path()));
        let call = ToolCall {
            name: "read_source".to_string(),
            // Missing required `file`.
            input: json!({}),
            call_id: "c1".to_string(),
        };
        // The driver wraps anyhow errors as is_error results — but our
        // tool handler returns Err for schema failures so the driver path
        // would convert it. Here we verify the closure returns Err.
        let res = crate::runtime::ToolCallHandler::run(&mut tb, &call);
        assert!(res.is_err());
    }

    #[test]
    fn tool_specs_have_expected_names() {
        let specs = code_nav_tool_specs();
        let names: Vec<_> = specs.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "read_source",
                "find_references",
                "list_definitions",
                "read_definition"
            ]
        );
    }

    #[test]
    fn code_nav_tool_names_match_registered_tool_names() {
        assert_eq!(CodeNavTool::ReadSource.name(), "read_source");
        assert_eq!(CodeNavTool::FindReferences.name(), "find_references");
        assert_eq!(CodeNavTool::ListDefinitions.name(), "list_definitions");
        assert_eq!(CodeNavTool::ReadDefinition.name(), "read_definition");
    }

    #[test]
    fn definition_tools_round_trip_via_toolbox() {
        if !rg_available() {
            eprintln!("rg not on PATH; skipping");
            return;
        }
        let tmp = tempdir().unwrap();
        fs::write(
            tmp.path().join("lib.rs"),
            "pub struct User { id: u64 }\n\nfn load_user() -> User { User { id: 1 } }\n",
        )
        .unwrap();
        let mut tb = code_nav_toolbox(CodeNavConfig::new(tmp.path()));

        let list = crate::runtime::ToolCallHandler::run(
            &mut tb,
            &ToolCall {
                name: "list_definitions".to_string(),
                input: json!({ "file": "lib.rs" }),
                call_id: "list".to_string(),
            },
        )
        .unwrap();
        assert!(!list.is_error, "{list:?}");
        assert!(list.output["definitions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["name"] == json!("load_user")));

        let read = crate::runtime::ToolCallHandler::run(
            &mut tb,
            &ToolCall {
                name: "read_definition".to_string(),
                input: json!({ "name": "load_user" }),
                call_id: "read".to_string(),
            },
        )
        .unwrap();
        assert!(!read.is_error, "{read:?}");
        assert!(read.output["source"]
            .as_str()
            .unwrap()
            .contains("fn load_user"));
    }
}
