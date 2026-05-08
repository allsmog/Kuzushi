use super::*;

pub(crate) fn detect_validation_plan(repo_root: &Path) -> PatchValidationPlan {
    VALIDATION_PLAN_RULES
        .iter()
        .find(|rule| rule.matches(repo_root))
        .map(ValidationPlanRule::plan)
        .unwrap_or_else(empty_validation_plan)
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
