use super::*;

pub(crate) fn detect_validation_plan(repo_root: &Path) -> PatchValidationPlan {
    VALIDATION_PLAN_RULES
        .iter()
        .find(|rule| rule.matches(repo_root))
        .map(ValidationPlanRule::plan)
        .unwrap_or_else(empty_validation_plan)
}

/// Resolve repository-derived validation commands during canonical input
/// preparation so approval and execution are bound to the same plan.
pub(crate) fn bind_patch_validation_plan(repo_root: &Path, input: &mut Value) -> Result<()> {
    let detected = detect_validation_plan(repo_root);
    let build = optional_string_alias(input, &["buildCmd", "buildCommand", "build_cmd"])?
        .or(detected.build);
    let test =
        optional_string_alias(input, &["testCmd", "testCommand", "test_cmd"])?.or(detected.test);
    let plan = PatchValidationPlan { build, test };
    ensure_patch_validation_plan(&plan)?;
    let object = input
        .as_object_mut()
        .context("patch:finding input must be an object")?;
    bind_optional_command(object, "buildCmd", plan.build);
    bind_optional_command(object, "testCmd", plan.test);
    Ok(())
}

fn bind_optional_command(object: &mut Map<String, Value>, key: &str, command: Option<String>) {
    if let Some(command) = command {
        object.insert(key.to_string(), Value::String(command));
    } else {
        object.remove(key);
    }
}

pub(crate) fn ensure_patch_validation_plan(plan: &PatchValidationPlan) -> Result<()> {
    anyhow::ensure!(
        plan.build.is_some() || plan.test.is_some(),
        "patch:finding requires at least one build or test validation command; repository validation was not detected, provide buildCmd or testCmd explicitly"
    );
    Ok(())
}

/// Operator-facing disclosure for the repository-owned commands that
/// `patch:finding` will execute after synthesizing a candidate diff.
pub fn patch_validation_disclosure(_repo_root: &Path, input: &Value) -> Result<String> {
    let build = optional_string_alias(input, &["buildCmd", "buildCommand", "build_cmd"])?;
    let test = optional_string_alias(input, &["testCmd", "testCommand", "test_cmd"])?;
    let source_commit = patch_source_commit(input)?;
    let plan = PatchValidationPlan { build, test };
    ensure_patch_validation_plan(&plan)?;
    Ok(validation_plan_disclosure(&plan, &source_commit))
}

#[cfg(test)]
mod binding_tests {
    use super::*;

    #[test]
    fn repository_plan_is_bound_once_before_markers_change() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::write(repo.path().join("Cargo.toml"), "[package]\nname='demo'\n").unwrap();
        let source_commit = "0123456789012345678901234567890123456789";
        let mut input = json!({
            "fingerprint": "abc",
            (PATCH_SOURCE_COMMIT_INPUT_KEY): source_commit,
        });

        bind_patch_validation_plan(repo.path(), &mut input).unwrap();
        std::fs::remove_file(repo.path().join("Cargo.toml")).unwrap();
        std::fs::write(repo.path().join("package.json"), "{}").unwrap();

        assert_eq!(input["buildCmd"], "cargo build");
        assert_eq!(input["testCmd"], "cargo test");
        let disclosure = patch_validation_disclosure(repo.path(), &input).unwrap();
        assert!(disclosure.contains(source_commit));
        assert!(disclosure.contains("cargo build ; cargo test"));
        assert!(!disclosure.contains("npm"));
    }

    #[test]
    fn unknown_repository_requires_an_explicit_validation_command() {
        let repo = tempfile::tempdir().unwrap();
        let mut input = json!({
            "fingerprint": "abc",
            (PATCH_SOURCE_COMMIT_INPUT_KEY): "0123456789012345678901234567890123456789",
        });

        let error = bind_patch_validation_plan(repo.path(), &mut input).unwrap_err();

        assert!(error.to_string().contains("requires at least one build or test validation command"));
        assert!(input.get("buildCmd").is_none());
        assert!(input.get("testCmd").is_none());
    }

    #[test]
    fn unknown_repository_accepts_an_explicit_test_command() {
        let repo = tempfile::tempdir().unwrap();
        let mut input = json!({
            "fingerprint": "abc",
            (PATCH_SOURCE_COMMIT_INPUT_KEY): "0123456789012345678901234567890123456789",
            "testCmd": "custom-test",
        });

        bind_patch_validation_plan(repo.path(), &mut input).unwrap();

        assert_eq!(input["testCmd"], "custom-test");
        assert!(input.get("buildCmd").is_none());
    }
}

pub(crate) fn validation_plan_disclosure(
    plan: &PatchValidationPlan,
    source_commit: &str,
) -> String {
    let commands = [plan.build.as_deref(), plan.test.as_deref()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let commands = if commands.is_empty() {
        "no build/test validation configured".to_string()
    } else {
        commands.join(" ; ")
    };
    format!(
        "source commit: {source_commit}; repository validation commands: {commands}; disposable worktree; {}; minimal environment",
        crate::remediation::patch_process_adapter::patch_network_isolation_disclosure()
    )
}

struct ValidationPlanRule {
    markers: &'static [&'static str],
    build: Option<&'static str>,
    test: Option<&'static str>,
}

impl ValidationPlanRule {
    fn matches(&self, repo_root: &Path) -> bool {
        self.markers
            .iter()
            .any(|marker| repo_root.join(marker).exists())
    }

    fn plan(&self) -> PatchValidationPlan {
        PatchValidationPlan {
            build: self.build.map(ToString::to_string),
            test: self.test.map(ToString::to_string),
        }
    }
}

const VALIDATION_PLAN_RULES: &[ValidationPlanRule] = &[
    ValidationPlanRule {
        markers: &["package.json"],
        build: Some("npm run build"),
        test: Some("npm test"),
    },
    ValidationPlanRule {
        markers: &["Makefile"],
        build: Some("make"),
        test: Some("make test"),
    },
    ValidationPlanRule {
        markers: &["Cargo.toml"],
        build: Some("cargo build"),
        test: Some("cargo test"),
    },
    ValidationPlanRule {
        markers: &["setup.py", "pyproject.toml"],
        build: None,
        test: Some("python -m pytest"),
    },
    ValidationPlanRule {
        markers: &["go.mod"],
        build: Some("go build ./..."),
        test: Some("go test ./..."),
    },
];

fn empty_validation_plan() -> PatchValidationPlan {
    PatchValidationPlan {
        build: None,
        test: None,
    }
}

pub(crate) fn optional_string_alias(input: &Value, keys: &[&str]) -> Result<Option<String>> {
    for key in keys {
        match input.get(*key) {
            Some(Value::String(value)) => {
                return Ok(Some(value.trim().to_string()).filter(|value| !value.is_empty()));
            }
            Some(_) => anyhow::bail!("patch:finding {key} must be a string"),
            None => {}
        }
    }
    Ok(None)
}

pub(crate) fn read_object_value<'a>(
    object: &'a Map<String, Value>,
    keys: &[&str],
) -> Option<&'a Value> {
    keys.iter().find_map(|key| object.get(*key))
}

pub(crate) fn read_object_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    read_object_value(object, keys)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub(crate) fn read_object_raw_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    read_object_value(object, keys)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToString::to_string)
}
