use super::*;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const APK_MAGIC: [u8; 4] = [b'P', b'K', 0x03, 0x04];

pub(in crate::modules) fn prepare_apk(input: &Value, target: &Path) -> Result<PreparedApk> {
    let apk_path = resolve_apk_path(input)?;
    validate_apk_magic(&apk_path)?;
    let decompiler = read_decompiler_choice(input)?;
    let tools = AndroidApkToolchain::from_tool_input(input);
    let workspace = AndroidApkWorkspace::create(target)?;
    workspace.run_unzip(&apk_path, &tools)?;
    if matches!(decompiler, Decompiler::Jadx | Decompiler::Both) {
        workspace.run_jadx(&apk_path, &tools)?;
    }
    if matches!(decompiler, Decompiler::Apktool | Decompiler::Both) {
        workspace.run_apktool(&apk_path, &tools)?;
    }
    Ok(PreparedApk {
        apk: apk_path,
        decompiler,
        workspace,
    })
}

fn resolve_apk_path(input: &Value) -> Result<PathBuf> {
    let raw = read_apk_string(input)?;
    let expanded = expand_home(raw);
    let path = PathBuf::from(&expanded);
    if !path.is_file() {
        anyhow::bail!("android-apk:prepare: apk path {raw:?} is not a readable file");
    }
    Ok(path)
}

fn read_apk_string(input: &Value) -> Result<&str> {
    input
        .get("apk")
        .and_then(Value::as_str)
        .or_else(|| input.get("apkPath").and_then(Value::as_str))
        .or_else(|| input.get("apk_path").and_then(Value::as_str))
        .or_else(|| input.get("file").and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("android-apk:prepare requires 'apk': path to the .apk file"))
}

fn expand_home(raw: &str) -> String {
    if let Some(stripped) = raw.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped).display().to_string();
        }
    }
    raw.to_string()
}

fn validate_apk_magic(path: &Path) -> Result<()> {
    let mut head = [0u8; 4];
    let bytes_read = read_head(path, &mut head)?;
    if bytes_read < 4 || head != APK_MAGIC {
        anyhow::bail!(
            "android-apk:prepare: file {} is not a ZIP/APK archive (bad magic)",
            path.display()
        );
    }
    Ok(())
}

fn read_head(path: &Path, head: &mut [u8]) -> Result<usize> {
    use std::io::Read;
    let mut file = fs::File::open(path)
        .map_err(|error| anyhow::anyhow!("could not open {}: {error}", path.display()))?;
    let mut total = 0usize;
    while total < head.len() {
        match file.read(&mut head[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(error) => anyhow::bail!("read error on {}: {error}", path.display()),
        }
    }
    Ok(total)
}

fn read_decompiler_choice(input: &Value) -> Result<Decompiler> {
    let raw = input
        .get("decompiler")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("both");
    match raw {
        "jadx" => Ok(Decompiler::Jadx),
        "apktool" => Ok(Decompiler::Apktool),
        "both" => Ok(Decompiler::Both),
        other => anyhow::bail!(
            "android-apk:prepare: unknown decompiler {other:?} (expected jadx, apktool, or both)"
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::modules) enum Decompiler {
    Jadx,
    Apktool,
    Both,
}

impl Decompiler {
    fn as_str(self) -> &'static str {
        match self {
            Self::Jadx => "jadx",
            Self::Apktool => "apktool",
            Self::Both => "both",
        }
    }
}

#[derive(Debug, Clone)]
pub(in crate::modules) struct AndroidApkWorkspace {
    root: PathBuf,
    decompiled_root: PathBuf,
    raw_dir: PathBuf,
    jadx_dir: PathBuf,
    apktool_dir: PathBuf,
}

impl AndroidApkWorkspace {
    fn create(workspace_root: &Path) -> Result<Self> {
        let decompiled_root = workspace_root.join("android-decompiled");
        let raw_dir = decompiled_root.join("raw");
        let jadx_dir = decompiled_root.join("jadx");
        let apktool_dir = decompiled_root.join("apktool");
        fs::create_dir_all(&decompiled_root).map_err(|error| {
            anyhow::anyhow!("could not create {}: {error}", decompiled_root.display())
        })?;
        Ok(Self {
            root: workspace_root.to_path_buf(),
            decompiled_root,
            raw_dir,
            jadx_dir,
            apktool_dir,
        })
    }

    fn run_unzip(&self, apk: &Path, tools: &AndroidApkToolchain) -> Result<()> {
        reset_dir(&self.raw_dir)?;
        let status = Command::new(&tools.unzip)
            .arg("-q")
            .arg("-o")
            .arg(apk)
            .arg("-d")
            .arg(&self.raw_dir)
            .status()
            .map_err(|error| missing_tool_error("unzip", &tools.unzip, error))?;
        if !status.success() {
            anyhow::bail!(
                "unzip exited with status {status} when extracting {}",
                apk.display()
            );
        }
        Ok(())
    }

    fn run_jadx(&self, apk: &Path, tools: &AndroidApkToolchain) -> Result<()> {
        reset_dir(&self.jadx_dir)?;
        let status = Command::new(&tools.jadx)
            .arg("--no-res")
            .arg("--show-bad-code")
            .arg("-d")
            .arg(&self.jadx_dir)
            .arg(apk)
            .status()
            .map_err(|error| missing_tool_error("jadx", &tools.jadx, error))?;
        if !status.success() {
            anyhow::bail!(
                "jadx exited with status {status} when decompiling {}",
                apk.display()
            );
        }
        Ok(())
    }

    fn run_apktool(&self, apk: &Path, tools: &AndroidApkToolchain) -> Result<()> {
        reset_dir(&self.apktool_dir)?;
        let status = Command::new(&tools.apktool)
            .arg("d")
            .arg("-f")
            .arg("-o")
            .arg(&self.apktool_dir)
            .arg(apk)
            .status()
            .map_err(|error| missing_tool_error("apktool", &tools.apktool, error))?;
        if !status.success() {
            anyhow::bail!(
                "apktool exited with status {status} when decoding {}",
                apk.display()
            );
        }
        Ok(())
    }
}

fn reset_dir(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_dir_all(path)
            .map_err(|error| anyhow::anyhow!("could not clear {}: {error}", path.display()))?;
    }
    fs::create_dir_all(path)
        .map_err(|error| anyhow::anyhow!("could not create {}: {error}", path.display()))
}

#[derive(Debug, Clone)]
pub(in crate::modules) struct PreparedApk {
    apk: PathBuf,
    decompiler: Decompiler,
    workspace: AndroidApkWorkspace,
}

impl PreparedApk {
    pub(in crate::modules) fn to_tool_json(&self) -> Value {
        let jadx_present = matches!(self.decompiler, Decompiler::Jadx | Decompiler::Both);
        let apktool_present = matches!(self.decompiler, Decompiler::Apktool | Decompiler::Both);
        let summary = format!(
            "android-apk: prepared {} into {}",
            self.apk.display(),
            self.workspace.decompiled_root.display()
        );
        json!({
            "ok": true,
            "summary": summary,
            "output": summary,
            "data": {
                "apk": self.apk.display().to_string(),
                "decompiler": self.decompiler.as_str(),
                "workspaceRoot": self.workspace.root.display().to_string(),
                "decompiledRoot": self.workspace.decompiled_root.display().to_string(),
                "rawDir": self.workspace.raw_dir.display().to_string(),
                "jadxDir": jadx_present.then(|| self.workspace.jadx_dir.display().to_string()),
                "apktoolDir": apktool_present.then(|| self.workspace.apktool_dir.display().to_string()),
                "nextSteps": [
                    format!("kuzushi scan {}", self.workspace.decompiled_root.display()),
                    "kuzushi findings --severity high,critical",
                ],
            },
            "warnings": [],
            "errors": [],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_zip_fixture(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(&APK_MAGIC).unwrap();
        file.write_all(&[0u8; 26]).unwrap();
        path
    }

    fn write_non_zip(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(b"not a zip").unwrap();
        path
    }

    #[test]
    fn validate_magic_accepts_zip_header() {
        let dir = tempdir().unwrap();
        let path = write_zip_fixture(dir.path(), "good.apk");
        validate_apk_magic(&path).expect("zip magic accepted");
    }

    #[test]
    fn validate_magic_rejects_non_zip() {
        let dir = tempdir().unwrap();
        let path = write_non_zip(dir.path(), "bad.apk");
        let error = validate_apk_magic(&path).expect_err("non-zip rejected");
        assert!(error.to_string().contains("not a ZIP/APK archive"));
    }

    #[test]
    fn resolve_apk_path_errors_when_missing() {
        let error = resolve_apk_path(&json!({})).expect_err("missing apk rejected");
        assert!(error.to_string().contains("requires 'apk'"));
    }

    #[test]
    fn resolve_apk_path_errors_on_directory() {
        let dir = tempdir().unwrap();
        let input = json!({"apk": dir.path().display().to_string()});
        let error = resolve_apk_path(&input).expect_err("directory rejected");
        assert!(error.to_string().contains("not a readable file"));
    }

    #[test]
    fn resolve_apk_path_accepts_alias_keys() {
        let dir = tempdir().unwrap();
        let path = write_zip_fixture(dir.path(), "alias.apk");
        let input = json!({"apkPath": path.display().to_string()});
        let resolved = resolve_apk_path(&input).expect("alias resolved");
        assert_eq!(resolved, path);
    }

    #[test]
    fn read_decompiler_choice_defaults_to_both() {
        assert_eq!(
            read_decompiler_choice(&json!({})).unwrap(),
            Decompiler::Both
        );
    }

    #[test]
    fn read_decompiler_choice_rejects_unknown() {
        let error =
            read_decompiler_choice(&json!({"decompiler": "ghidra"})).expect_err("unknown rejected");
        assert!(error.to_string().contains("unknown decompiler"));
    }

    #[test]
    fn workspace_create_makes_decompiled_root() {
        let dir = tempdir().unwrap();
        let workspace = AndroidApkWorkspace::create(dir.path()).expect("workspace created");
        assert!(workspace.decompiled_root.is_dir());
        assert_eq!(
            workspace.decompiled_root,
            dir.path().join("android-decompiled")
        );
    }
}
