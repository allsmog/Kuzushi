use super::prelude::*;
use super::*;

pub(crate) fn detect_validation_plan(repo_root: &Path) -> PatchValidationPlan {
    if repo_root.join("package.json").exists() {
        return PatchValidationPlan {
            build: Some("npm run build".to_string()),
            test: Some("npm test".to_string()),
        };
    }
    if repo_root.join("Makefile").exists() {
        return PatchValidationPlan {
            build: Some("make".to_string()),
            test: Some("make test".to_string()),
        };
    }
    if repo_root.join("Cargo.toml").exists() {
        return PatchValidationPlan {
            build: Some("cargo build".to_string()),
            test: Some("cargo test".to_string()),
        };
    }
    if repo_root.join("setup.py").exists() || repo_root.join("pyproject.toml").exists() {
        return PatchValidationPlan {
            build: None,
            test: Some("python -m pytest".to_string()),
        };
    }
    if repo_root.join("go.mod").exists() {
        return PatchValidationPlan {
            build: Some("go build ./...".to_string()),
            test: Some("go test ./...".to_string()),
        };
    }
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
