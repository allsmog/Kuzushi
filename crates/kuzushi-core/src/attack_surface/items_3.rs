use super::prelude::*;
use super::*;

pub(crate) fn inspect_source_file(
    root: &Path,
    source_file: &InventorySourceFile,
    builder: &mut AttackSurfaceBuilder,
) -> Result<()> {
    let full_path = root.join(&source_file.path);
    let bytes = fs::read(&full_path)
        .with_context(|| format!("Could not read source file {}", full_path.display()))?;
    if bytes.iter().take(4096).any(|byte| *byte == 0) {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&bytes);
    let framework = framework_for_source(&source_file.language, &text);

    for (index, line) in text.lines().enumerate() {
        let line_number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        inspect_line(
            source_file,
            framework.as_deref(),
            line_number,
            line,
            builder,
        );
    }

    Ok(())
}

pub(crate) fn inspect_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    line: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    match source_file.language.as_str() {
        "JavaScript" | "TypeScript" => {
            inspect_node_line(source_file, framework, line_number, line, builder);
        }
        "Python" => inspect_python_line(source_file, framework, line_number, line, builder),
        "Go" => inspect_go_line(source_file, framework, line_number, line, builder),
        "Rust" => inspect_rust_line(source_file, framework, line_number, line, builder),
        _ => {}
    }
}
