use super::*;

pub(super) struct ContextLimits {
    pub source: SourcePrefixLimits,
    pub max_surfaces: usize,
    pub include_non_production: bool,
}

impl ContextLimits {
    pub fn parse(input: &Value) -> Result<Self> {
        let canonical = canonical_input(input)?;
        Ok(Self {
            source: SourcePrefixLimits {
                max_files: limit(&canonical, "maxFiles", 5000, 100_000)?,
                max_bytes: limit(
                    &canonical,
                    "maxSourceBytes",
                    16 * 1024 * 1024,
                    512 * 1024 * 1024,
                )?,
                max_file_bytes: limit(&canonical, "headBytes", 16384, 256 * 1024)?,
            },
            max_surfaces: limit(&canonical, "maxSurfaces", 50, 1000)?,
            include_non_production: canonical["includeNonProduction"].as_bool().unwrap_or(false),
        })
    }
}

fn canonical_input(input: &Value) -> Result<Value> {
    // Direct compatibility callers receive the same option validation as dispatch.
    let registry = crate::modules::ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let canonical = registry.prepare_tool_input(
        "systems-hunt:systems-context-gatherer",
        input.clone(),
        None,
    )?;
    let fields = canonical
        .as_object()
        .context("systems context input must be an object")?;
    for name in fields.keys() {
        anyhow::ensure!(
            supported_key(name),
            "{name} is unsupported by standalone systems context; remove this option"
        );
    }
    Ok(canonical)
}

fn supported_key(name: &str) -> bool {
    matches!(
        name,
        "target"
            | "maxFiles"
            | "maxSourceBytes"
            | "headBytes"
            | "maxSurfaces"
            | "includeNonProduction"
            | "allowanceRef"
    )
}

fn limit(input: &Value, name: &str, default: usize, maximum: usize) -> Result<usize> {
    let value = input.get(name).map_or(Ok(default), |value| {
        let number = value
            .as_u64()
            .context(format!("{name} must be a positive integer"))?;
        usize::try_from(number).context(format!("{name} exceeds this platform's range"))
    })?;
    anyhow::ensure!(
        (1..=maximum).contains(&value),
        "{name} must be between 1 and {maximum}"
    );
    Ok(value)
}

pub(super) fn selected_path(relative: &str, include_non_production: bool) -> bool {
    let path = Path::new(relative);
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !SYSTEMS_EXTENSIONS.contains(&extension.as_str()) {
        return false;
    }
    if relative.split('/').any(|part| SKIP_DIRS.contains(&part)) {
        return false;
    }
    include_non_production || production_path(path, relative)
}

fn production_path(path: &Path, relative: &str) -> bool {
    is_systems_source(path)
        && !relative
            .split('/')
            .any(|part| NON_PRODUCTION_SYSTEMS_DIRS.contains(&part))
}
