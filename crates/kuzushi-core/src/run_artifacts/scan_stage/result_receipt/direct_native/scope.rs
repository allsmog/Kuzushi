use super::*;
use std::collections::BTreeSet;

pub(super) fn validate(
    target: &Path,
    id: &str,
    result: &Value,
    scan: &ScanStageData,
) -> Result<()> {
    anyhow::ensure!(
        Path::new(&scan.scope.target) == target,
        "Direct scan workspace differs from its coverage"
    );
    anyhow::ensure!(
        scan.target_snapshot.target == scan.scope.target,
        "Direct scan source target differs from its coverage"
    );
    let paths = expected_paths(target, id, result)?;
    anyhow::ensure!(
        scan.scope.paths == paths,
        "Direct scan paths differ from its selected target"
    );
    let members = scan
        .scope
        .inspected_files
        .as_ref()
        .context("Direct scan inspected-file membership is unavailable")?;
    anyhow::ensure!(
        members
            .iter()
            .all(|file| valid_relative(file) && scan.scope.covers_file(file)),
        "Direct scan membership escapes its selected scope"
    );
    let expected = expected_members(id, result, &paths)?;
    anyhow::ensure!(
        *members == expected,
        "Direct scan membership differs from its inspected files"
    );
    Ok(())
}

fn expected_paths(target: &Path, id: &str, result: &Value) -> Result<Vec<String>> {
    let selected = result
        .pointer("/data/target")
        .and_then(Value::as_str)
        .context("Direct scan target is unavailable")?;
    let relative = Path::new(selected)
        .strip_prefix(target)
        .context("Direct scan selected target is outside its workspace")?;
    let path = if id == "cargo-audit" {
        relative.join("Cargo.lock")
    } else {
        relative.to_path_buf()
    };
    if path.as_os_str().is_empty() {
        return Ok(vec![".".into()]);
    }
    let path = path.to_string_lossy().replace('\\', "/");
    anyhow::ensure!(
        valid_relative(&path),
        "Direct scan selected path is invalid"
    );
    Ok(vec![path])
}

fn expected_members(id: &str, result: &Value, paths: &[String]) -> Result<BTreeSet<String>> {
    if id == "cargo-audit" {
        return Ok(paths.iter().cloned().collect());
    }
    let members: BTreeSet<String> = serde_json::from_value(
        result
            .pointer("/data/inspectedFiles")
            .cloned()
            .context("IaC inspected files are unavailable")?,
    )?;
    anyhow::ensure!(
        result.pointer("/data/filesScanned").and_then(Value::as_u64) == Some(members.len() as u64),
        "IaC inspected files contradict its file count"
    );
    Ok(members)
}

fn valid_relative(file: &str) -> bool {
    !file.is_empty()
        && !file.contains('\\')
        && file.split('/').all(|part| !matches!(part, "" | "." | ".."))
        && !Path::new(file).is_absolute()
}
