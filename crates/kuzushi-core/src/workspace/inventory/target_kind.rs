//! Cheap, bounded classification of what *kind* of target a workspace is, so
//! the phase walker can preselect the right tasks (e.g. reverse-engineering for
//! an APK or native binary, SAST for a source tree). This is intentionally a
//! shallow scan — it must be fast even on a multi-gigabyte decompiled APK, so
//! it stops as soon as it has decisive evidence or hits a file-count budget.

use std::path::Path;

/// The broad shape of an analysis target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    /// A plain source tree (the common case).
    Source,
    /// A JVM application (jars/classes) without Android markers.
    JvmApp,
    /// A decompiled / unpacked Android app (smali, AndroidManifest, dex).
    AndroidApk,
    /// A tree containing native compiled binaries (ELF / Mach-O / shared libs).
    NativeBinary,
}

impl TargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TargetKind::Source => "source",
            TargetKind::JvmApp => "jvm-app",
            TargetKind::AndroidApk => "android-apk",
            TargetKind::NativeBinary => "native-binary",
        }
    }

    /// Whether reverse-engineering tasks are worth preselecting for this kind.
    pub fn is_reverse_engineering_target(self) -> bool {
        matches!(self, TargetKind::AndroidApk | TargetKind::NativeBinary)
    }
}

const SCAN_FILE_BUDGET: usize = 20_000;

#[derive(Default)]
struct KindEvidence {
    android: bool,
    native: bool,
    jvm: bool,
}

/// Classify `target` with a bounded directory walk. Decisive Android markers
/// short-circuit immediately; otherwise we tally extensions up to a budget.
pub fn classify_target_kind(target: &Path) -> TargetKind {
    if has_android_marker(target) {
        return TargetKind::AndroidApk;
    }
    let evidence = scan_for_kind_evidence(target);
    resolve_kind(&evidence)
}

fn resolve_kind(evidence: &KindEvidence) -> TargetKind {
    if evidence.android {
        TargetKind::AndroidApk
    } else if evidence.native {
        TargetKind::NativeBinary
    } else if evidence.jvm {
        TargetKind::JvmApp
    } else {
        TargetKind::Source
    }
}

fn has_android_marker(target: &Path) -> bool {
    ["AndroidManifest.xml", "apktool.yml", "smali", "classes.dex"]
        .iter()
        .any(|marker| target.join(marker).exists())
}

fn scan_for_kind_evidence(target: &Path) -> KindEvidence {
    let mut evidence = KindEvidence::default();
    let mut stack = vec![target.to_path_buf()];
    let mut budget = SCAN_FILE_BUDGET;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if budget == 0 || evidence.android {
                return evidence;
            }
            budget -= 1;
            absorb_entry(&entry, &mut evidence, &mut stack);
        }
    }
    evidence
}

fn absorb_entry(
    entry: &std::fs::DirEntry,
    evidence: &mut KindEvidence,
    stack: &mut Vec<std::path::PathBuf>,
) {
    let path = entry.path();
    if path.is_dir() {
        if !is_skippable_dir(&path) {
            stack.push(path);
        }
        return;
    }
    note_extension_evidence(&path, evidence);
}

fn note_extension_evidence(path: &Path, evidence: &mut KindEvidence) {
    let Some(ext) = path.extension().and_then(|ext| ext.to_str()) else {
        return;
    };
    match ext.to_ascii_lowercase().as_str() {
        "smali" | "dex" | "apk" => evidence.android = true,
        "so" | "dylib" | "dll" | "elf" | "o" | "a" => evidence.native = true,
        "jar" | "class" => evidence.jvm = true,
        _ => {}
    }
}

fn is_skippable_dir(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some(".git" | "node_modules" | ".kuzushi" | "target" | "vendor")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn android_manifest_marks_apk() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("AndroidManifest.xml"), "<manifest/>").unwrap();
        assert_eq!(classify_target_kind(tmp.path()), TargetKind::AndroidApk);
    }

    #[test]
    fn smali_files_mark_apk() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.smali"), ".class").unwrap();
        assert_eq!(classify_target_kind(tmp.path()), TargetKind::AndroidApk);
        assert!(TargetKind::AndroidApk.is_reverse_engineering_target());
    }

    #[test]
    fn shared_objects_mark_native() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("libfoo.so"), "\x7fELF").unwrap();
        assert_eq!(classify_target_kind(tmp.path()), TargetKind::NativeBinary);
    }

    #[test]
    fn plain_source_tree_is_source() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("main.py"), "print(1)").unwrap();
        assert_eq!(classify_target_kind(tmp.path()), TargetKind::Source);
        assert!(!TargetKind::Source.is_reverse_engineering_target());
    }

    #[test]
    fn jars_without_android_are_jvm() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("app.jar"), "PK").unwrap();
        assert_eq!(classify_target_kind(tmp.path()), TargetKind::JvmApp);
    }
}
