use super::*;

use goblin::elf::Elf;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const DANGEROUS_IMPORTS: &[&str] = &[
    "system", "popen", "execve", "execvp", "execv", "execle", "execl", "execlp", "dlopen", "dlsym",
    "mmap", "mprotect", "ptrace", "fork", "syscall", "strcpy", "strcat", "sprintf", "gets",
];

#[derive(Debug)]
pub(in crate::modules) struct NativeLibSummary {
    pub(in crate::modules) path: PathBuf,
    pub(in crate::modules) abi: String,
    pub(in crate::modules) size_bytes: u64,
    pub(in crate::modules) jni_exports: Vec<String>,
    pub(in crate::modules) dangerous_imports: Vec<String>,
}

pub(in crate::modules) fn summarize_lib(path: &Path) -> Result<NativeLibSummary> {
    let bytes = fs::read(path)?;
    let elf = Elf::parse(&bytes)?;
    let abi = path
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .to_string();
    let symbols = collect_symbols(&elf);
    Ok(NativeLibSummary {
        path: path.to_path_buf(),
        abi,
        size_bytes: bytes.len() as u64,
        jni_exports: symbols.jni_exports,
        dangerous_imports: symbols.dangerous_imports,
    })
}

struct LibSymbols {
    jni_exports: Vec<String>,
    dangerous_imports: Vec<String>,
}

fn collect_symbols(elf: &Elf<'_>) -> LibSymbols {
    let strtab = &elf.dynstrtab;
    let mut jni_exports = BTreeSet::new();
    let mut dangerous_imports = BTreeSet::new();
    for sym in elf.dynsyms.iter() {
        if let Some(name) = strtab.get_at(sym.st_name) {
            classify_dynsym(name, &sym, &mut jni_exports, &mut dangerous_imports);
        }
    }
    LibSymbols {
        jni_exports: jni_exports.into_iter().collect(),
        dangerous_imports: dangerous_imports.into_iter().collect(),
    }
}

fn classify_dynsym(
    name: &str,
    sym: &goblin::elf::sym::Sym,
    jni_exports: &mut BTreeSet<String>,
    dangerous_imports: &mut BTreeSet<String>,
) {
    if name.starts_with("Java_") && sym.st_value != 0 {
        jni_exports.insert(name.to_string());
        return;
    }
    if sym.st_value == 0 && DANGEROUS_IMPORTS.contains(&name) {
        dangerous_imports.insert(name.to_string());
    }
}

pub(in crate::modules) fn enumerate_so_files(lib_root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for abi_entry in fs::read_dir(lib_root)
        .map_err(|error| anyhow::anyhow!("could not read {}: {error}", lib_root.display()))?
    {
        let abi_entry = match abi_entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let abi_path = abi_entry.path();
        if !abi_path.is_dir() {
            continue;
        }
        collect_so_in_abi(&abi_path, &mut paths);
    }
    Ok(paths)
}

fn collect_so_in_abi(abi_path: &Path, paths: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(abi_path) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if is_shared_object(&path) {
            paths.push(path);
        }
    }
}

fn is_shared_object(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("so"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn workspace_with_libs(abi: &str, names: &[&str]) -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        let lib_root = dir.path().join("lib").join(abi);
        fs::create_dir_all(&lib_root).unwrap();
        for name in names {
            fs::write(lib_root.join(name), b"\x7fELF").unwrap();
        }
        dir
    }

    #[test]
    fn enumerate_picks_up_so_files() {
        let dir = workspace_with_libs("arm64-v8a", &["libfoo.so", "libbar.so", "ignored.txt"]);
        let lib_root = dir.path().join("lib");
        let paths = enumerate_so_files(&lib_root).unwrap();
        let names: Vec<_> = paths
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str().map(str::to_string)))
            .collect();
        assert!(names.contains(&"libfoo.so".into()));
        assert!(names.contains(&"libbar.so".into()));
        assert!(!names.contains(&"ignored.txt".into()));
    }

    #[test]
    fn is_shared_object_recognizes_so_extension() {
        assert!(is_shared_object(Path::new("libfoo.so")));
        assert!(is_shared_object(Path::new("libfoo.SO")));
        assert!(!is_shared_object(Path::new("classes.dex")));
        assert!(!is_shared_object(Path::new("libfoo.so.1")));
    }
}
