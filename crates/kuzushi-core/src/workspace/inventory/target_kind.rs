//! Cheap, bounded classification of what *kind* of target a workspace is, so
//! the phase walker can preselect the right tasks (e.g. reverse-engineering for
//! an APK or native binary, SAST for a source tree). This is intentionally a
//! shallow scan — it must be fast even on a multi-gigabyte decompiled APK, so
//! it stops as soon as it has decisive evidence or hits a file-count budget.

use std::path::{Path, PathBuf};

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

const TARGET_PROFILE_FILE_BUDGET: usize = 20_000;

/// Bounded workspace evidence used by phase planning. It owns target-kind
/// classification so every caller consumes one shared policy and one walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetProfile {
    pub kind: TargetKind,
    pub has_c_family_source: bool,
    pub has_rust_source: bool,
    pub has_compile_commands: bool,
    pub has_reverse_engineering_artifact: bool,
}

impl TargetProfile {
    pub fn detect(target: &Path) -> Self {
        Self::detect_cancellable(target, || false).unwrap_or_else(Self::conservative)
    }

    pub fn detect_cancellable(target: &Path, is_cancelled: impl Fn() -> bool) -> Option<Self> {
        let evidence = TargetProfileScan::new(target).run(&is_cancelled)?;
        Some(Self {
            kind: evidence.kind(),
            has_c_family_source: evidence.has_c_family_source,
            has_rust_source: evidence.has_rust_source,
            has_compile_commands: target_has_compile_commands(target),
            has_reverse_engineering_artifact: evidence.has_reverse_engineering_artifact,
        })
    }

    pub fn conservative() -> Self {
        Self {
            kind: TargetKind::Source,
            has_c_family_source: false,
            has_rust_source: false,
            has_compile_commands: false,
            has_reverse_engineering_artifact: false,
        }
    }

    pub fn has_systems_surface(self) -> bool {
        self.kind == TargetKind::NativeBinary || self.has_c_family_source || self.has_rust_source
    }
}

/// Preserve the public classifier while delegating its evidence policy to the
/// shared profile used by planning.
pub fn classify_target_kind(target: &Path) -> TargetKind {
    if has_android_marker(target) {
        return TargetKind::AndroidApk;
    }
    TargetProfile::detect(target).kind
}

#[derive(Default)]
struct TargetProfileEvidence {
    android: bool,
    native: bool,
    jvm: bool,
    has_c_family_source: bool,
    has_rust_source: bool,
    has_reverse_engineering_artifact: bool,
}

impl TargetProfileEvidence {
    fn kind(&self) -> TargetKind {
        if self.android {
            return TargetKind::AndroidApk;
        }
        if self.native {
            return TargetKind::NativeBinary;
        }
        if self.jvm {
            return TargetKind::JvmApp;
        }
        TargetKind::Source
    }

    fn observe_root(&mut self, target: &Path) {
        self.android = has_android_marker(target);
        self.has_reverse_engineering_artifact = root_is_reverse_artifact(target);
    }

    fn observe_file(&mut self, path: &Path) {
        let Some(extension) = path.extension().and_then(|ext| ext.to_str()) else {
            return;
        };
        let extension = extension.to_ascii_lowercase();
        self.observe_kind_extension(&extension);
        self.observe_source_extension(&extension);
        self.observe_reverse_extension(&extension);
    }

    fn observe_kind_extension(&mut self, extension: &str) {
        if matches!(extension, "smali" | "dex" | "apk") {
            self.android = true;
            return;
        }
        if matches!(extension, "so" | "dylib" | "dll" | "elf" | "o" | "a") {
            self.native = true;
            return;
        }
        if matches!(extension, "jar" | "class") {
            self.jvm = true;
        }
    }

    fn observe_source_extension(&mut self, extension: &str) {
        if c_family_extension(extension) {
            self.has_c_family_source = true;
        }
        if extension == "rs" {
            self.has_rust_source = true;
        }
    }

    fn observe_reverse_extension(&mut self, extension: &str) {
        self.has_reverse_engineering_artifact |= matches!(
            extension,
            "so" | "dylib" | "dll" | "exe" | "bin" | "elf" | "apk"
        );
    }
}

struct TargetProfileScan {
    evidence: TargetProfileEvidence,
    stack: Vec<PathBuf>,
    budget: usize,
}

impl TargetProfileScan {
    fn new(target: &Path) -> Self {
        let mut evidence = TargetProfileEvidence::default();
        evidence.observe_root(target);
        Self {
            evidence,
            stack: vec![target.to_path_buf()],
            budget: TARGET_PROFILE_FILE_BUDGET,
        }
    }

    fn run(mut self, is_cancelled: &impl Fn() -> bool) -> Option<TargetProfileEvidence> {
        while self.scan_next_directory(is_cancelled)? {}
        Some(self.evidence)
    }

    fn scan_next_directory(&mut self, is_cancelled: &impl Fn() -> bool) -> Option<bool> {
        let Some(directory) = self.stack.pop() else {
            return Some(false);
        };
        self.scan_directory(&directory, is_cancelled)
    }

    fn scan_directory(
        &mut self,
        directory: &Path,
        is_cancelled: &impl Fn() -> bool,
    ) -> Option<bool> {
        if is_cancelled() {
            return None;
        }
        let Ok(entries) = std::fs::read_dir(directory) else {
            return Some(true);
        };
        self.scan_entries(entries, is_cancelled)
    }

    fn scan_entries(
        &mut self,
        entries: std::fs::ReadDir,
        is_cancelled: &impl Fn() -> bool,
    ) -> Option<bool> {
        for entry in entries.flatten() {
            if !self.visit_path(entry.path(), is_cancelled)? {
                return Some(false);
            }
        }
        Some(true)
    }

    fn visit_path(&mut self, path: PathBuf, is_cancelled: &impl Fn() -> bool) -> Option<bool> {
        if is_cancelled() {
            return None;
        }
        if self.budget == 0 {
            return Some(false);
        }
        self.budget -= 1;
        self.absorb_path(path);
        Some(true)
    }

    fn absorb_path(&mut self, path: PathBuf) {
        if path.is_dir() {
            if !is_skippable_dir(&path) {
                self.stack.push(path);
            }
            return;
        }
        self.evidence.observe_file(&path);
    }
}

fn c_family_extension(extension: &str) -> bool {
    matches!(
        extension,
        "c" | "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp" | "hxx" | "ipp" | "cu" | "cuh"
    )
}

fn has_android_marker(target: &Path) -> bool {
    ["AndroidManifest.xml", "apktool.yml", "smali", "classes.dex"]
        .iter()
        .any(|marker| target.join(marker).exists())
}

fn root_is_reverse_artifact(target: &Path) -> bool {
    target.is_file() || target.join("classes.dex").is_file()
}

pub fn target_has_compile_commands(target: &Path) -> bool {
    ["compile_commands.json", "build/compile_commands.json"]
        .iter()
        .any(|relative| target.join(relative).is_file())
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

    #[test]
    fn target_profile_collects_kind_source_and_build_evidence_in_one_walk() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("build")).unwrap();
        std::fs::write(tmp.path().join("main.c"), "int main(void) { return 0; }").unwrap();
        std::fs::write(tmp.path().join("lib.rs"), "pub fn run() {}").unwrap();
        std::fs::write(tmp.path().join("libfoo.so"), "\x7fELF").unwrap();
        std::fs::write(tmp.path().join("build/compile_commands.json"), "[]").unwrap();

        let profile = TargetProfile::detect(tmp.path());

        assert_eq!(profile.kind, TargetKind::NativeBinary);
        assert!(profile.has_c_family_source);
        assert!(profile.has_rust_source);
        assert!(profile.has_compile_commands);
        assert!(profile.has_reverse_engineering_artifact);
    }

    #[test]
    fn cancellable_target_profile_stops_before_returning_stale_evidence() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("main.rs"), "fn main() {}").unwrap();
        let checks = std::cell::Cell::new(0_usize);

        let profile = TargetProfile::detect_cancellable(tmp.path(), || {
            checks.set(checks.get() + 1);
            checks.get() > 1
        });

        assert!(profile.is_none());
    }
}
