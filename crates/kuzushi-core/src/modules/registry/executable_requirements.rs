use super::*;

/// A declared executable option after canonical option preparation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExecutableRequirement {
    pub option: String,
    pub command: String,
}

impl ModuleRegistry {
    pub fn executable_requirements(
        &self,
        name: &str,
        prepared: &Value,
    ) -> Vec<ExecutableRequirement> {
        let Some(tool) = self.resolve_tool(name) else {
            return Vec::new();
        };
        tool.options
            .iter()
            .filter(|option| option.path_semantics == Some(PathSemantics::Executable))
            .filter_map(|option| {
                prepared
                    .get(&option.name)?
                    .as_str()
                    .map(|command| ExecutableRequirement {
                        option: option.name.clone(),
                        command: command.to_string(),
                    })
            })
            .collect()
    }
}

/// Presence inspection only. This never invokes a command or certifies a tool.
pub fn missing_executable_requirements(requirements: &[ExecutableRequirement]) -> Vec<String> {
    requirements
        .iter()
        .filter(|requirement| !crate::process_lookup::executable_available(&requirement.command))
        .map(|requirement| requirement.option.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn semgrep_preserves_the_exact_executable_filename_in_presence_and_preflight() {
        use crate::scan::ScanEngine;
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("owned scanner ");
        std::fs::write(&binary, "Owned inert file. Never invoked.").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let input = registry
            .prepare_tool_input("semgrep:scan", json!({"scannerBin":binary}), None)
            .unwrap();
        assert_eq!(
            registry.executable_requirements("semgrep:scan", &input)[0].command,
            binary.to_str().unwrap()
        );
        let scanner = crate::scan::SemgrepScanner::from_tool_input(&input).unwrap();
        assert_eq!(scanner.binary, binary.to_str().unwrap());
        assert!(scanner.preflight().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn shared_semgrep_dispatch_reports_a_nonexecutable_dependency_without_scanning() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("owned-scanner");
        std::fs::write(&binary, "Owned inert file. Never invoked.").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o600)).unwrap();
        let workspace = crate::WorkspaceTarget::new(temp.path()).unwrap();
        let store = crate::FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = crate::V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let registry = ModuleRegistry::with_v2_builtins();
        let prepared = registry
            .prepare_dispatch_input("semgrep:scan", json!({"binary":binary}), &ctx, None)
            .unwrap()
            .authorize_explicit_headless();
        let outcome = registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
            .unwrap();
        assert_eq!(outcome["status"], "failed");
        assert!(outcome["output"]
            .as_str()
            .unwrap()
            .contains("could not find scanner binary"));
        assert!(store.list_all_findings().unwrap().is_empty());
    }

    #[test]
    fn prepared_aliases_and_defaults_supply_declared_executable_requirements() {
        let registry = ModuleRegistry::with_v2_builtins();
        let defaults = registry
            .prepare_tool_input("semgrep:scan", json!({}), None)
            .unwrap();
        assert_eq!(
            registry.executable_requirements("semgrep:scan", &defaults),
            vec![ExecutableRequirement {
                option: "binary".into(),
                command: crate::scan::SemgrepScanner::default().binary
            }]
        );
        let input = registry
            .prepare_tool_input(
                "semgrep:scan",
                json!({"scannerBin":"/missing/owned-scanner"}),
                None,
            )
            .unwrap();
        let requirements = registry.executable_requirements("semgrep:scan", &input);
        assert_eq!(requirements[0].command, "/missing/owned-scanner");
        assert_eq!(
            missing_executable_requirements(&requirements),
            vec!["binary"]
        );
        let codeql = registry
            .prepare_tool_input("codeql:scan", json!({}), None)
            .unwrap();
        assert!(codeql.get("binary").is_none());
        assert!(registry
            .executable_requirements("codeql:scan", &codeql)
            .is_empty());
    }

    #[test]
    fn data_paths_and_undeclared_input_cannot_become_executable_requirements() {
        let registry = ModuleRegistry::with_v2_builtins();
        assert!(registry
            .executable_requirements(
                "threat-model:read",
                &json!({"path":"/missing","binary":"/missing"})
            )
            .is_empty());
        assert!(registry
            .executable_requirements("missing:tool", &json!({"binary":"/missing"}))
            .is_empty());
    }
}
