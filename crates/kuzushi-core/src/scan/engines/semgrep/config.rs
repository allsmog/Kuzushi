use super::*;
use crate::scan::domain::scanner_binary_available;

pub(crate) fn parse_semgrep_config_input(input: &Value) -> Result<Option<Vec<String>>> {
    let Some(raw) = input.get("config").or_else(|| input.get("configFlag")) else {
        return Ok(None);
    };
    Ok(Some(default_semgrep_configs(semgrep_configs_from_value(
        raw,
    )?)))
}

fn semgrep_configs_from_value(raw: &Value) -> Result<Vec<String>> {
    if let Some(value) = raw.as_str() {
        return Ok(vec![value.trim().to_string()]);
    }
    if let Some(values) = raw.as_array() {
        return values.iter().map(semgrep_config_array_entry).collect();
    }
    anyhow::bail!("semgrep: config/configFlag must be a string or string array")
}

fn semgrep_config_array_entry(value: &Value) -> Result<String> {
    value
        .as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(ToString::to_string)
        .context("semgrep: config/configFlag array entries must be non-empty strings")
}

fn default_semgrep_configs(configs: Vec<String>) -> Vec<String> {
    let configs = non_empty_semgrep_configs(configs);
    if configs.is_empty() {
        vec!["auto".to_string()]
    } else {
        configs
    }
}

fn non_empty_semgrep_configs(configs: Vec<String>) -> Vec<String> {
    configs
        .into_iter()
        .filter(|value| !value.is_empty())
        .collect()
}

pub(in crate::scan) fn semgrep_missing_binary_error(binary: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "semgrep: could not find scanner binary {:?}. Install Semgrep (for example `pipx install semgrep` or `brew install semgrep`). To use a custom binary: `kuzushi --target <repo> run semgrep:scan --input '{{\"binary\":\"/path/to/semgrep\"}}'`. To continue without Semgrep: `kuzushi scan <repo> --tasks dep-hygiene,secret-scan,license-scan,iac-scan --ci`.",
        binary
    )
}

impl ScanEngine for SemgrepScanner {
    fn id(&self) -> &'static str {
        "semgrep"
    }

    fn preflight(&self) -> Result<()> {
        if scanner_binary_available(&self.binary) {
            return Ok(());
        }
        Err(semgrep_missing_binary_error(&self.binary))
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        self.scan_with_cancel(target, cancellation)
    }
}
