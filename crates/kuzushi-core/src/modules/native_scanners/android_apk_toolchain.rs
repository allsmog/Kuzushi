use super::*;

use std::process::Command;

#[derive(Debug, Clone)]
pub(in crate::modules) struct AndroidApkToolchain {
    pub(in crate::modules) jadx: String,
    pub(in crate::modules) apktool: String,
    pub(in crate::modules) unzip: String,
}

impl AndroidApkToolchain {
    pub(in crate::modules) fn from_tool_input(input: &Value) -> Self {
        Self {
            jadx: read_bin(input, &["jadxBin", "jadx_bin", "jadx"]).unwrap_or_else(|| "jadx".into()),
            apktool: read_bin(input, &["apktoolBin", "apktool_bin", "apktool"]).unwrap_or_else(|| "apktool".into()),
            unzip: read_bin(input, &["unzipBin", "unzip_bin", "unzip"]).unwrap_or_else(|| "unzip".into()),
        }
    }
}

fn read_bin(input: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = input.get(*key).and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

#[derive(Debug, Clone)]
pub(in crate::modules) struct ToolchainEntry {
    pub(in crate::modules) name: &'static str,
    pub(in crate::modules) binary: String,
    pub(in crate::modules) found: bool,
    pub(in crate::modules) resolved_path: Option<String>,
    pub(in crate::modules) version_line: Option<String>,
}

#[derive(Debug, Clone)]
pub(in crate::modules) struct ToolchainReport {
    pub(in crate::modules) entries: Vec<ToolchainEntry>,
}

impl ToolchainReport {
    pub(in crate::modules) fn probe(tools: &AndroidApkToolchain) -> Self {
        let entries = vec![
            probe_tool("jadx", &tools.jadx, &["--version"]),
            probe_tool("apktool", &tools.apktool, &["--version"]),
            probe_tool("unzip", &tools.unzip, &["-v"]),
        ];
        Self { entries }
    }

    pub(in crate::modules) fn missing_count(&self) -> usize {
        self.entries.iter().filter(|entry| !entry.found).count()
    }

    pub(in crate::modules) fn to_tool_json(&self) -> Value {
        let missing = self
            .entries
            .iter()
            .filter(|entry| !entry.found)
            .map(|entry| entry.name)
            .collect::<Vec<_>>();
        let summary = if missing.is_empty() {
            "android-apk: all required tools are available on PATH".to_string()
        } else {
            format!("android-apk: missing tools: {}", missing.join(", "))
        };
        json!({
            "ok": missing.is_empty(),
            "summary": summary,
            "output": summary,
            "data": {
                "tools": self.entries.iter().map(toolchain_entry_json).collect::<Vec<_>>(),
                "missing": missing,
            },
            "warnings": [],
            "errors": [],
        })
    }
}

fn toolchain_entry_json(entry: &ToolchainEntry) -> Value {
    json!({
        "name": entry.name,
        "binary": entry.binary,
        "found": entry.found,
        "resolvedPath": entry.resolved_path,
        "versionLine": entry.version_line,
    })
}

fn probe_tool(name: &'static str, binary: &str, version_args: &[&str]) -> ToolchainEntry {
    let resolved_path = which_binary(binary);
    let found = resolved_path.is_some();
    let version_line = if found {
        run_version_probe(binary, version_args)
    } else {
        None
    };
    ToolchainEntry {
        name,
        binary: binary.to_string(),
        found,
        resolved_path,
        version_line,
    }
}

fn which_binary(binary: &str) -> Option<String> {
    let output = Command::new("which").arg(binary).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

fn run_version_probe(binary: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(binary).args(args).output().ok()?;
    let combined = [&output.stdout[..], &output.stderr[..]].concat();
    String::from_utf8_lossy(&combined)
        .lines()
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
}

pub(in crate::modules) fn missing_tool_error(name: &str, binary: &str, error: std::io::Error) -> anyhow::Error {
    if error.kind() == std::io::ErrorKind::NotFound {
        anyhow::anyhow!(
            "android-apk: could not find {name} binary {binary:?}. Install {name} or pass {{\"{name}Bin\":\"/path/to/{name}\"}} in the tool input."
        )
    } else {
        anyhow::anyhow!("android-apk: failed to spawn {name} ({binary:?}): {error}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn toolchain_defaults_to_path_names() {
        let tools = AndroidApkToolchain::from_tool_input(&json!({}));
        assert_eq!(tools.jadx, "jadx");
        assert_eq!(tools.apktool, "apktool");
        assert_eq!(tools.unzip, "unzip");
    }

    #[test]
    fn toolchain_picks_up_overrides() {
        let tools = AndroidApkToolchain::from_tool_input(&json!({
            "jadxBin": "/opt/jadx/bin/jadx",
            "apktool": "/usr/local/bin/apktool",
            "unzip_bin": "/bin/unzip",
        }));
        assert_eq!(tools.jadx, "/opt/jadx/bin/jadx");
        assert_eq!(tools.apktool, "/usr/local/bin/apktool");
        assert_eq!(tools.unzip, "/bin/unzip");
    }

    #[test]
    fn missing_count_zero_when_all_found() {
        let report = ToolchainReport {
            entries: vec![
                ToolchainEntry { name: "jadx", binary: "jadx".into(), found: true, resolved_path: Some("/usr/bin/jadx".into()), version_line: None },
                ToolchainEntry { name: "apktool", binary: "apktool".into(), found: true, resolved_path: Some("/usr/bin/apktool".into()), version_line: None },
            ],
        };
        assert_eq!(report.missing_count(), 0);
    }

    #[test]
    fn missing_count_counts_unfound() {
        let report = ToolchainReport {
            entries: vec![
                ToolchainEntry { name: "jadx", binary: "jadx".into(), found: false, resolved_path: None, version_line: None },
                ToolchainEntry { name: "apktool", binary: "apktool".into(), found: true, resolved_path: Some("/usr/bin/apktool".into()), version_line: None },
                ToolchainEntry { name: "unzip", binary: "unzip".into(), found: false, resolved_path: None, version_line: None },
            ],
        };
        assert_eq!(report.missing_count(), 2);
    }

    #[test]
    fn missing_tool_error_mentions_install_hint() {
        let io = std::io::Error::from(std::io::ErrorKind::NotFound);
        let error = missing_tool_error("jadx", "jadx", io);
        let message = error.to_string();
        assert!(message.contains("could not find jadx"));
        assert!(message.contains("jadxBin"));
    }
}
