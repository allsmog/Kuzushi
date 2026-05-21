use super::*;

mod detectors;

use detectors::DOTNET_LINE_DETECTORS;

pub(crate) fn inspect_dotnet_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    line: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let detail = trim_detail(line);
    let lower = detail.to_ascii_lowercase();
    for detector in DOTNET_LINE_DETECTORS {
        if detector.matches(&lower) {
            builder.add(detector.surface(source_file, framework, line_number, &detail));
        }
    }
}
