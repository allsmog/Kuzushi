//! `binary-analysis` — deterministic compiled-binary inspection.
//!
//! Walks a target tree, identifies ELF / PE / Mach-O / Wasm binaries by
//! magic bytes, and reports missing hardening flags plus historically-
//! dangerous imports. Pure Rust, no external tools (`readelf`, `objdump`,
//! `dumpbin`), no LLM, no network — runs identically in `kuzushi scan`,
//! the shell's `run`, and `kuzushi run`.
//!
//! The crate-level pattern is the same one [`secret_scan`] uses:
//!
//! 1. `BinaryAnalysisOptions::from_tool_input` parses the tool JSON.
//! 2. `scan_binaries` walks the directory, identifies binaries, dispatches
//!    per-format checks, and aggregates `BinaryAnalysisFinding`s.
//! 3. `BinaryAnalysisFinding::to_core_finding` adapts each entry into a
//!    canonical `Finding` for the findings store.
//! 4. `BinaryAnalysisScanner` exposes the same engine through the
//!    [`ScanEngine`] trait so the DAG / `kuzushi scan --tasks
//!    binary-analysis` path also goes through it.
//!
//! Parsers are intentionally minimal — just enough fields to evaluate the
//! checks below. They are total over arbitrary byte input: malformed
//! files yield `None` (or partial info), never panics. The scanner treats
//! `None` as "skip this file" so a corrupt artefact does not abort the
//! walk.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::findings::{Finding, Severity};
use crate::scan::{ScanCancellation, ScanEngine};

const DEFAULT_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_MAX_FINDINGS: usize = 1000;
/// Read at most this many bytes from each candidate file. The binary
/// headers we care about all sit at fixed offsets near the start of the
/// file, plus the dynamic-string table we scan for symbol names.
const HEADER_PEEK_BYTES: usize = 2 * 1024 * 1024;

const DEFAULT_EXCLUDE_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    "third_party",
    "third-party",
    ".cache",
    ".turbo",
    "coverage",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
];

/// Curated list of historically-dangerous libc / Win32 imports. Matching
/// one of these is not a vulnerability per se — it is a signal worth
/// surfacing to an operator auditing a third-party binary. The list stays
/// small intentionally so the false-positive rate stays manageable.
const RISKY_IMPORTS: &[&str] = &[
    // C string handling without bounds
    "gets",
    "strcpy",
    "strcat",
    "sprintf",
    "vsprintf",
    "scanf",
    "sscanf",
    "fscanf",
    // Process / shell
    "system",
    "popen",
    // Crypto APIs commonly misused
    "MD5_Init",
    "MD5_Update",
    "MD5_Final",
    "SHA1_Init",
    "SHA1_Update",
    "SHA1_Final",
    "DES_set_key",
    "RC4",
    // Win32 helpers prone to misuse
    "WinExec",
    "ShellExecute",
    "ShellExecuteA",
    "ShellExecuteW",
    "LoadLibrary",
    "LoadLibraryA",
    "LoadLibraryW",
];

// ---------------------------------------------------------------------------
// Public option / report / finding types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BinaryAnalysisOptions {
    pub max_file_bytes: u64,
    pub exclude_dirs: BTreeSet<String>,
    pub max_findings: usize,
    pub severity: Option<BTreeSet<BinarySeverity>>,
}

impl Default for BinaryAnalysisOptions {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            exclude_dirs: DEFAULT_EXCLUDE_DIRS
                .iter()
                .map(|entry| (*entry).to_string())
                .collect(),
            max_findings: DEFAULT_MAX_FINDINGS,
            severity: None,
        }
    }
}

impl BinaryAnalysisOptions {
    pub fn from_tool_input(input: &Value) -> Result<Self> {
        let mut options = Self::default();

        if let Some(value) = input.get("maxFileBytes").and_then(Value::as_u64) {
            options.max_file_bytes = value.max(1024);
        }

        if let Some(value) = input.get("maxFindings").and_then(Value::as_u64) {
            options.max_findings = value.clamp(1, 10_000) as usize;
        }

        if let Some(values) = input.get("excludeDirs").and_then(Value::as_array) {
            for value in values.iter().filter_map(Value::as_str) {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    options.exclude_dirs.insert(trimmed.to_string());
                }
            }
        }

        if let Some(values) = input.get("severity").and_then(Value::as_array) {
            let mut severities = BTreeSet::new();
            for value in values.iter().filter_map(Value::as_str) {
                severities.insert(BinarySeverity::try_from(value)?);
            }
            options.severity = Some(severities);
        }

        Ok(options)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BinaryAnalysisReport {
    pub target: String,
    pub findings: Vec<BinaryAnalysisFinding>,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub binaries_identified: usize,
}

impl BinaryAnalysisReport {
    pub fn output(&self) -> String {
        let summary = if self.findings.is_empty() {
            "no hardening or risky-import issues".to_string()
        } else {
            let mut counts = BTreeMap::<&'static str, usize>::new();
            for finding in &self.findings {
                *counts.entry(finding.severity.as_str()).or_default() += 1;
            }
            counts
                .into_iter()
                .map(|(severity, count)| format!("{count} {}", severity.to_ascii_lowercase()))
                .collect::<Vec<_>>()
                .join(", ")
        };

        let mut lines = vec![
            format!(
                "binary-analysis: {} finding{} ({summary})",
                self.findings.len(),
                if self.findings.len() == 1 { "" } else { "s" }
            ),
            format!("  Binaries identified: {}", self.binaries_identified),
            format!("  Files scanned:       {}", self.files_scanned),
            format!("  Files skipped:       {}", self.files_skipped),
            format!("  Target:              {}", self.target),
        ];

        if !self.findings.is_empty() {
            lines.push(String::new());
            lines.push("Top findings:".to_string());
            for finding in self.findings.iter().take(10) {
                lines.push(format!(
                    "  - {} - {} - {}",
                    finding.severity.as_str(),
                    finding.rule_id,
                    finding.file_path,
                ));
            }
            if self.findings.len() > 10 {
                lines.push(format!("  ... and {} more", self.findings.len() - 10));
            }
        }

        lines.join("\n")
    }

    pub fn to_tool_json(&self) -> Value {
        json!({
            "ok": true,
            "output": self.output(),
            "data": {
                "findings": self.findings,
                "filesScanned": self.files_scanned,
                "filesSkipped": self.files_skipped,
                "binariesIdentified": self.binaries_identified,
                "target": self.target,
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BinaryAnalysisFinding {
    pub task_id: String,
    pub fingerprint: String,
    pub rule_id: String,
    pub file_path: String,
    pub format: String,
    pub severity: BinarySeverity,
    pub message: String,
    pub evidence: String,
    pub cwe: Vec<String>,
}

impl BinaryAnalysisFinding {
    pub fn to_core_finding(&self) -> Finding {
        let mut finding = Finding::new_tool(
            "binary-analysis",
            self.rule_id.clone(),
            self.file_path.clone(),
            1,
            None,
            self.severity.to_core_severity(),
            format!("{}\n{}", self.message, self.evidence),
        );
        finding.fingerprint = self.fingerprint.clone();
        finding.title = self.message.clone();
        finding
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BinarySeverity {
    Error,
    Warning,
    Info,
}

impl BinarySeverity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warning => "WARNING",
            Self::Info => "INFO",
        }
    }

    fn to_core_severity(self) -> Severity {
        match self {
            Self::Error => Severity::High,
            Self::Warning => Severity::Medium,
            Self::Info => Severity::Info,
        }
    }
}

impl TryFrom<&str> for BinarySeverity {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::result::Result<Self, anyhow::Error> {
        match value {
            "ERROR" => Ok(Self::Error),
            "WARNING" => Ok(Self::Warning),
            "INFO" => Ok(Self::Info),
            other => anyhow::bail!("unknown binary-analysis severity {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// ScanEngine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct BinaryAnalysisScanner;

impl ScanEngine for BinaryAnalysisScanner {
    fn id(&self) -> &'static str {
        "binary-analysis"
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        let report = scan_binaries(target, &BinaryAnalysisOptions::default(), cancellation)?;
        Ok(report
            .findings
            .iter()
            .map(BinaryAnalysisFinding::to_core_finding)
            .collect())
    }
}

// ---------------------------------------------------------------------------
// scan_binaries — public entrypoint
// ---------------------------------------------------------------------------

pub fn scan_binaries(
    target: &Path,
    options: &BinaryAnalysisOptions,
    cancellation: &ScanCancellation,
) -> Result<BinaryAnalysisReport> {
    let root = canonical_directory(target)?;
    let mut files = Vec::new();
    collect_files(&root, options, &mut files)?;

    let mut findings = Vec::new();
    let mut files_scanned = 0usize;
    let mut files_skipped = 0usize;
    let mut binaries_identified = 0usize;

    'outer: for file_path in files {
        if cancellation.is_cancelled() {
            anyhow::bail!("binary-analysis scan cancelled");
        }

        let Ok(metadata) = fs::metadata(&file_path) else {
            continue;
        };
        if metadata.len() > options.max_file_bytes {
            files_skipped += 1;
            continue;
        }

        let Some(bytes) = read_capped(&file_path, options.max_file_bytes) else {
            continue;
        };
        files_scanned += 1;

        let Some(format) = identify_binary(&bytes) else {
            continue;
        };
        binaries_identified += 1;

        let rel_path = file_path
            .strip_prefix(&root)
            .unwrap_or(&file_path)
            .display()
            .to_string();
        let ctx = CheckCtx { repo_root: &root, rel_path: &rel_path };

        let new_findings = match format {
            BinaryFormat::Elf => parse_elf(&bytes).map(|info| check_elf(&info, &ctx)).unwrap_or_default(),
            BinaryFormat::Pe => parse_pe(&bytes).map(|info| check_pe(&info, &ctx)).unwrap_or_default(),
            BinaryFormat::Macho => parse_macho(&bytes).map(|info| check_macho(&info, &ctx)).unwrap_or_default(),
            BinaryFormat::MachoFat => Vec::new(),
            BinaryFormat::Wasm => parse_wasm(&bytes).map(|info| check_wasm(&info, &ctx)).unwrap_or_default(),
        };

        for finding in new_findings {
            findings.push(finding);
            if findings.len() >= options.max_findings {
                break 'outer;
            }
        }
    }

    if let Some(filter) = &options.severity {
        findings.retain(|finding| filter.contains(&finding.severity));
    }

    Ok(BinaryAnalysisReport {
        target: root.display().to_string(),
        findings,
        files_scanned,
        files_skipped,
        binaries_identified,
    })
}

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------

fn canonical_directory(target: &Path) -> Result<PathBuf> {
    let path = if target.is_absolute() {
        target.to_path_buf()
    } else {
        std::env::current_dir()
            .context("Could not resolve current directory")?
            .join(target)
    };
    if !path.exists() {
        anyhow::bail!(
            "binary-analysis: target is not a directory: {}",
            path.display()
        );
    }
    let canonical = fs::canonicalize(&path)
        .with_context(|| format!("binary-analysis: failed to resolve {}", path.display()))?;
    if !canonical.is_dir() {
        anyhow::bail!(
            "binary-analysis: target is not a directory: {}",
            canonical.display()
        );
    }
    Ok(canonical)
}

fn collect_files(
    dir: &Path,
    options: &BinaryAnalysisOptions,
    out: &mut Vec<PathBuf>,
) -> Result<()> {
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let file_name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            if options.exclude_dirs.contains(file_name.as_str()) {
                continue;
            }
            collect_files(&path, options, out)?;
        } else if file_type.is_file() {
            out.push(path);
        }
    }

    Ok(())
}

fn read_capped(path: &Path, cap: u64) -> Option<Vec<u8>> {
    let bytes = fs::read(path).ok()?;
    let take = std::cmp::min(bytes.len(), HEADER_PEEK_BYTES);
    let take = std::cmp::min(take as u64, cap) as usize;
    Some(bytes[..take].to_vec())
}

fn fingerprint_for(repo_root: &Path, rule_id: &str, file_path: &str) -> String {
    let repo_name = repo_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let input = format!("{repo_name}|binary-analysis|{rule_id}|{file_path}");
    format!(
        "binary-analysis:{rule_id}:{:016x}",
        fnv1a64(input.as_bytes())
    )
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

// ---------------------------------------------------------------------------
// Format identification + parsers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinaryFormat {
    Elf,
    Pe,
    Macho,
    MachoFat,
    Wasm,
}

/// Recognise the binary format from a buffer's first few bytes.
/// Returns `None` for unrecognised input (the scanner treats this as
/// "not a binary, skip").
fn identify_binary(buf: &[u8]) -> Option<BinaryFormat> {
    if buf.len() < 4 {
        return None;
    }
    if buf[0..4] == [0x7f, b'E', b'L', b'F'] {
        return Some(BinaryFormat::Elf);
    }
    if buf[0] == b'M' && buf[1] == b'Z' && buf.len() >= 0x40 {
        let pe_off = read_u32_le(buf, 0x3c)? as usize;
        if pe_off + 4 < buf.len() && buf[pe_off..pe_off + 4] == [b'P', b'E', 0, 0] {
            return Some(BinaryFormat::Pe);
        }
    }
    let m0 = read_u32_le(buf, 0)?;
    if matches!(m0, 0xfeed_face | 0xfeed_facf | 0xcefa_edfe | 0xcffa_edfe) {
        return Some(BinaryFormat::Macho);
    }
    // Mach-O FAT (universal binaries) stores its 0xCAFEBABE magic in
    // big-endian, so a byte-pattern check is clearer than reasoning about
    // the LE-read integer value. Java class files share this magic but
    // store a major version (>= 45) in the next word; Mach-O FAT stores a
    // small architecture count. Capping nfat at 32 separates them
    // reliably without parsing further.
    if buf.len() >= 8 && buf[0..4] == [0xCA, 0xFE, 0xBA, 0xBE] {
        let nfat = read_u32_be(buf, 4)?;
        if nfat > 0 && nfat <= 32 {
            return Some(BinaryFormat::MachoFat);
        }
    }
    if buf[0..4] == [0x00, b'a', b's', b'm'] {
        return Some(BinaryFormat::Wasm);
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ElfInfo {
    bits: u8,
    little_endian: bool,
    e_type: u16,
    nx_stack: bool,
    has_gnu_stack: bool,
    has_relro: bool,
    bind_now: bool,
    stack_canary: bool,
    risky_imports: Vec<String>,
}

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;

const DT_NULL: u64 = 0;
const DT_BIND_NOW: u64 = 24;
const DT_FLAGS: u64 = 30;
const DT_FLAGS_1: u64 = 0x6fff_fffb;
const DF_BIND_NOW: u64 = 0x8;
const DF_1_NOW: u64 = 0x1;

fn parse_elf(buf: &[u8]) -> Option<ElfInfo> {
    if buf.len() < 6 {
        return None;
    }
    let bits = match buf[4] {
        1 => 32,
        2 => 64,
        _ => return None,
    };
    let little_endian = match buf[5] {
        1 => true,
        2 => false,
        _ => return None,
    };
    let header_size = if bits == 64 { 64 } else { 52 };
    if buf.len() < header_size {
        return None;
    }

    let e_type = read_u16(buf, 16, little_endian)?;
    let (ph_off, ph_ent_size, ph_num) = if bits == 64 {
        (
            read_u64(buf, 32, little_endian)? as usize,
            read_u16(buf, 54, little_endian)? as usize,
            read_u16(buf, 56, little_endian)? as usize,
        )
    } else {
        (
            read_u32(buf, 28, little_endian)? as usize,
            read_u16(buf, 42, little_endian)? as usize,
            read_u16(buf, 44, little_endian)? as usize,
        )
    };

    let mut nx_stack = true;
    let mut has_gnu_stack = false;
    let mut has_relro = false;
    let mut dyn_offset: Option<usize> = None;
    let mut dyn_size: usize = 0;
    let mut load_segments: Vec<LoadSegment> = Vec::new();

    for i in 0..ph_num {
        let off = ph_off.checked_add(i.checked_mul(ph_ent_size)?)?;
        if off + ph_ent_size > buf.len() {
            break;
        }
        let p_type = read_u32(buf, off, little_endian)?;
        let flags = if bits == 64 {
            read_u32(buf, off + 4, little_endian)?
        } else {
            read_u32(buf, off + 24, little_endian)?
        };

        match p_type {
            PT_GNU_STACK => {
                has_gnu_stack = true;
                nx_stack = (flags & 0x1) == 0;
            }
            PT_GNU_RELRO => has_relro = true,
            PT_DYNAMIC => {
                let (file_off, size) = program_header_file_range(buf, off, bits, little_endian)?;
                dyn_offset = Some(file_off);
                dyn_size = size;
            }
            PT_LOAD => {
                if let Some(seg) = parse_load_segment(buf, off, bits, little_endian) {
                    load_segments.push(seg);
                }
            }
            _ => {}
        }
    }

    let (bind_now, strtab_addr, strtab_sz) =
        scan_dynamic_section(buf, dyn_offset, dyn_size, bits, little_endian);
    let (stack_canary, risky_imports) =
        scan_dynstr(buf, strtab_addr, strtab_sz, &load_segments);

    Some(ElfInfo {
        bits,
        little_endian,
        e_type,
        nx_stack,
        has_gnu_stack,
        has_relro,
        bind_now,
        stack_canary,
        risky_imports,
    })
}

#[derive(Debug, Clone, Copy)]
struct LoadSegment {
    file_offset: u64,
    virtual_addr: u64,
    file_size: u64,
}

fn program_header_file_range(
    buf: &[u8],
    ph_offset: usize,
    bits: u8,
    little_endian: bool,
) -> Option<(usize, usize)> {
    let (file_off, size) = if bits == 64 {
        (
            read_u64(buf, ph_offset + 8, little_endian)? as usize,
            read_u64(buf, ph_offset + 32, little_endian)? as usize,
        )
    } else {
        (
            read_u32(buf, ph_offset + 4, little_endian)? as usize,
            read_u32(buf, ph_offset + 16, little_endian)? as usize,
        )
    };
    Some((file_off, size))
}

fn parse_load_segment(
    buf: &[u8],
    ph_offset: usize,
    bits: u8,
    little_endian: bool,
) -> Option<LoadSegment> {
    if bits == 64 {
        Some(LoadSegment {
            file_offset: read_u64(buf, ph_offset + 8, little_endian)?,
            virtual_addr: read_u64(buf, ph_offset + 16, little_endian)?,
            file_size: read_u64(buf, ph_offset + 32, little_endian)?,
        })
    } else {
        Some(LoadSegment {
            file_offset: read_u32(buf, ph_offset + 4, little_endian)? as u64,
            virtual_addr: read_u32(buf, ph_offset + 8, little_endian)? as u64,
            file_size: read_u32(buf, ph_offset + 16, little_endian)? as u64,
        })
    }
}

fn scan_dynamic_section(
    buf: &[u8],
    dyn_offset: Option<usize>,
    dyn_size: usize,
    bits: u8,
    little_endian: bool,
) -> (bool, Option<u64>, usize) {
    let Some(start) = dyn_offset else {
        return (false, None, 0);
    };
    let end = start.saturating_add(dyn_size).min(buf.len());
    let entry_size = if bits == 64 { 16 } else { 8 };
    let mut bind_now = false;
    let mut strtab_addr: Option<u64> = None;
    let mut strtab_sz = 0usize;

    let mut off = start;
    while off + entry_size <= end {
        let (tag, value) = if bits == 64 {
            (
                read_u64(buf, off, little_endian).unwrap_or(0),
                read_u64(buf, off + 8, little_endian).unwrap_or(0),
            )
        } else {
            (
                read_u32(buf, off, little_endian).unwrap_or(0) as u64,
                read_u32(buf, off + 4, little_endian).unwrap_or(0) as u64,
            )
        };

        if tag == DT_NULL {
            break;
        }
        if tag == DT_BIND_NOW
            || (tag == DT_FLAGS && (value & DF_BIND_NOW) != 0)
            || (tag == DT_FLAGS_1 && (value & DF_1_NOW) != 0)
        {
            bind_now = true;
        } else if tag == 5 {
            // DT_STRTAB
            strtab_addr = Some(value);
        } else if tag == 10 {
            // DT_STRSZ
            strtab_sz = value as usize;
        }

        off += entry_size;
    }

    (bind_now, strtab_addr, strtab_sz)
}

fn scan_dynstr(
    buf: &[u8],
    strtab_addr: Option<u64>,
    strtab_sz: usize,
    load_segments: &[LoadSegment],
) -> (bool, Vec<String>) {
    let Some(addr) = strtab_addr else {
        return (false, Vec::new());
    };
    let Some(file_off) = virtual_to_file(load_segments, addr) else {
        return (false, Vec::new());
    };
    let end = file_off
        .saturating_add(strtab_sz as u64)
        .min(buf.len() as u64);
    if file_off >= buf.len() as u64 || end <= file_off {
        return (false, Vec::new());
    }
    let slice = &buf[file_off as usize..end as usize];
    let stack_canary = slice
        .windows("__stack_chk_fail".len())
        .any(|w| w == b"__stack_chk_fail")
        || slice
            .windows("__stack_chk_guard".len())
            .any(|w| w == b"__stack_chk_guard");
    let risky_imports = scan_risky_imports(slice);
    (stack_canary, risky_imports)
}

fn virtual_to_file(load_segments: &[LoadSegment], addr: u64) -> Option<u64> {
    for seg in load_segments {
        if addr >= seg.virtual_addr && addr < seg.virtual_addr.checked_add(seg.file_size)? {
            return Some(seg.file_offset + (addr - seg.virtual_addr));
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeInfo {
    bits: u8,
    dll_characteristics: u16,
    aslr: bool,
    high_entropy_va: bool,
    dep: bool,
    cfg: bool,
    no_seh: bool,
    risky_imports: Vec<String>,
}

const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
const IMAGE_DLLCHARACTERISTICS_NO_SEH: u16 = 0x0400;
const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;

fn parse_pe(buf: &[u8]) -> Option<PeInfo> {
    if buf.len() < 0x40 {
        return None;
    }
    let pe_off = read_u32_le(buf, 0x3c)? as usize;
    if pe_off + 26 > buf.len() {
        return None;
    }
    let opt_magic = read_u16_le(buf, pe_off + 24)?;
    let bits: u8 = if opt_magic == 0x20b { 64 } else { 32 };
    // DllCharacteristics offset is 70 from the start of the optional header
    // for both PE32 and PE32+ (the optional-header layout shifts the
    // ImageBase field width but leaves DllCharacteristics in the same slot
    // relative to the magic).
    let dll_char_off = pe_off + 24 + 70;
    if dll_char_off + 2 > buf.len() {
        return None;
    }
    let dll_char = read_u16_le(buf, dll_char_off)?;

    Some(PeInfo {
        bits,
        dll_characteristics: dll_char,
        aslr: (dll_char & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0,
        high_entropy_va: (dll_char & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0,
        dep: (dll_char & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0,
        cfg: (dll_char & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0,
        no_seh: (dll_char & IMAGE_DLLCHARACTERISTICS_NO_SEH) != 0,
        risky_imports: scan_risky_imports(buf),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MachoInfo {
    bits: u8,
    flags: u32,
    pie: bool,
}

const MH_PIE: u32 = 0x0020_0000;

fn parse_macho(buf: &[u8]) -> Option<MachoInfo> {
    if buf.len() < 28 {
        return None;
    }
    let magic = read_u32_le(buf, 0)?;
    let little_endian = matches!(magic, 0xfeed_face | 0xfeed_facf);
    let bits: u8 = if matches!(magic, 0xfeed_facf | 0xcffa_edfe) {
        64
    } else {
        32
    };
    let flags = read_u32(buf, 24, little_endian)?;
    Some(MachoInfo {
        bits,
        flags,
        pie: (flags & MH_PIE) != 0,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WasmInfo {
    version: u32,
}

fn parse_wasm(buf: &[u8]) -> Option<WasmInfo> {
    if buf.len() < 8 {
        return None;
    }
    Some(WasmInfo {
        version: read_u32_le(buf, 4)?,
    })
}

fn scan_risky_imports(buf: &[u8]) -> Vec<String> {
    let mut found = Vec::new();
    let mut seen = BTreeSet::new();
    for &name in RISKY_IMPORTS {
        if seen.contains(name) {
            continue;
        }
        if contains_nul_anchored(buf, name.as_bytes()) {
            found.push(name.to_string());
            seen.insert(name);
        }
    }
    found
}

fn contains_nul_anchored(buf: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return false;
    }
    // Imports inside ELF / PE string tables are NUL-terminated. Anchor on
    // a NUL on the leading side (or buffer start) and require either NUL
    // or 0x01 (sometimes used in PE import tables) trailing — this avoids
    // matching the tail of an unrelated symbol like `mystrcpy`.
    let mut i = 0;
    while i + needle.len() < buf.len() {
        if let Some(found) = buf[i..].windows(needle.len()).position(|w| w == needle) {
            let start = i + found;
            let end = start + needle.len();
            let leading_ok = start == 0 || buf[start - 1] == 0;
            let trailing_ok = end < buf.len() && (buf[end] == 0 || buf[end] == 0x01);
            if leading_ok && trailing_ok {
                return true;
            }
            i = start + 1;
        } else {
            return false;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Hardening checks
// ---------------------------------------------------------------------------

struct CheckCtx<'a> {
    repo_root: &'a Path,
    rel_path: &'a str,
}

const ET_DYN: u16 = 3;

fn check_elf(info: &ElfInfo, ctx: &CheckCtx<'_>) -> Vec<BinaryAnalysisFinding> {
    let mut findings = Vec::new();

    if info.e_type != ET_DYN {
        findings.push(make_finding(
            ctx,
            "elf-missing-pie",
            "elf",
            BinarySeverity::Warning,
            "ELF binary built without PIE — image base is fixed, defeating ASLR.",
            &format!("e_type={} (expected ET_DYN=3)", info.e_type),
            &["CWE-1037"],
        ));
    }

    if info.has_gnu_stack && !info.nx_stack {
        findings.push(make_finding(
            ctx,
            "elf-executable-stack",
            "elf",
            BinarySeverity::Error,
            "ELF binary marks the stack as executable (PT_GNU_STACK with PF_X set).",
            "PT_GNU_STACK p_flags has PF_X bit set",
            &["CWE-119"],
        ));
    } else if !info.has_gnu_stack {
        findings.push(make_finding(
            ctx,
            "elf-missing-gnu-stack",
            "elf",
            BinarySeverity::Warning,
            "ELF binary has no PT_GNU_STACK header — stack-NX status is unspecified.",
            "no PT_GNU_STACK program header",
            &["CWE-119"],
        ));
    }

    if !info.has_relro {
        findings.push(make_finding(
            ctx,
            "elf-missing-relro",
            "elf",
            BinarySeverity::Warning,
            "ELF binary built without RELRO — GOT and .dynamic remain writable.",
            "no PT_GNU_RELRO program header",
            &["CWE-1037"],
        ));
    } else if !info.bind_now {
        findings.push(make_finding(
            ctx,
            "elf-partial-relro",
            "elf",
            BinarySeverity::Info,
            "ELF binary has partial RELRO only — full RELRO requires DT_BIND_NOW.",
            "PT_GNU_RELRO present but no DT_BIND_NOW / DF_BIND_NOW / DF_1_NOW",
            &["CWE-1037"],
        ));
    }

    if !info.stack_canary {
        findings.push(make_finding(
            ctx,
            "elf-missing-stack-canary",
            "elf",
            BinarySeverity::Warning,
            "ELF binary appears to be built without stack canaries.",
            "no __stack_chk_fail / __stack_chk_guard symbol in dynstr",
            &["CWE-121"],
        ));
    }

    let _ = info.bits;
    let _ = info.little_endian;

    for sym in &info.risky_imports {
        findings.push(make_finding(
            ctx,
            &format!("risky-import-{sym}"),
            "elf",
            BinarySeverity::Info,
            &format!("ELF binary imports historically-dangerous symbol \"{sym}\"."),
            &format!("dynamic-string-table reference to {sym}"),
            cwe_for_risky_import(sym),
        ));
    }

    findings
}

fn check_pe(info: &PeInfo, ctx: &CheckCtx<'_>) -> Vec<BinaryAnalysisFinding> {
    let mut findings = Vec::new();
    let dll_hex = format!("0x{:04x}", info.dll_characteristics);

    if !info.aslr {
        findings.push(make_finding(
            ctx,
            "pe-missing-aslr",
            "pe",
            BinarySeverity::Warning,
            "PE binary built without ASLR (DllCharacteristics DYNAMIC_BASE clear).",
            &format!("DllCharacteristics={dll_hex}"),
            &["CWE-1037"],
        ));
    } else if info.bits == 64 && !info.high_entropy_va {
        findings.push(make_finding(
            ctx,
            "pe-missing-high-entropy-va",
            "pe",
            BinarySeverity::Info,
            "PE64 binary lacks HIGH_ENTROPY_VA — ASLR uses only the low 32 bits of address space.",
            &format!("DllCharacteristics={dll_hex}"),
            &["CWE-1037"],
        ));
    }

    if !info.dep {
        findings.push(make_finding(
            ctx,
            "pe-missing-dep",
            "pe",
            BinarySeverity::Error,
            "PE binary built without DEP/NX (DllCharacteristics NX_COMPAT clear).",
            &format!("DllCharacteristics={dll_hex}"),
            &["CWE-119"],
        ));
    }

    if !info.cfg {
        findings.push(make_finding(
            ctx,
            "pe-missing-cfg",
            "pe",
            BinarySeverity::Info,
            "PE binary built without Control Flow Guard (DllCharacteristics GUARD_CF clear).",
            &format!("DllCharacteristics={dll_hex}"),
            &["CWE-1037"],
        ));
    }

    if info.no_seh {
        findings.push(make_finding(
            ctx,
            "pe-no-seh",
            "pe",
            BinarySeverity::Info,
            "PE binary opts out of SafeSEH (DllCharacteristics NO_SEH set).",
            &format!("DllCharacteristics={dll_hex}"),
            &["CWE-1037"],
        ));
    }

    for sym in &info.risky_imports {
        findings.push(make_finding(
            ctx,
            &format!("risky-import-{sym}"),
            "pe",
            BinarySeverity::Info,
            &format!("PE binary imports historically-dangerous function \"{sym}\"."),
            &format!("import-table reference to {sym}"),
            cwe_for_risky_import(sym),
        ));
    }

    findings
}

fn check_macho(info: &MachoInfo, ctx: &CheckCtx<'_>) -> Vec<BinaryAnalysisFinding> {
    let mut findings = Vec::new();
    if !info.pie {
        findings.push(make_finding(
            ctx,
            "macho-missing-pie",
            "macho",
            BinarySeverity::Warning,
            "Mach-O binary built without MH_PIE — defeats ASLR for the executable image.",
            &format!("flags=0x{:08x}", info.flags),
            &["CWE-1037"],
        ));
    }
    let _ = info.bits;
    findings
}

fn check_wasm(info: &WasmInfo, ctx: &CheckCtx<'_>) -> Vec<BinaryAnalysisFinding> {
    if info.version == 1 {
        return Vec::new();
    }
    vec![make_finding(
        ctx,
        "wasm-unexpected-version",
        "wasm",
        BinarySeverity::Info,
        &format!(
            "WebAssembly module declares unexpected version {} (expected 1).",
            info.version
        ),
        &format!("module version field = {}", info.version),
        &[],
    )]
}

fn make_finding(
    ctx: &CheckCtx<'_>,
    rule_id: &str,
    format: &str,
    severity: BinarySeverity,
    message: &str,
    evidence: &str,
    cwe: &[&str],
) -> BinaryAnalysisFinding {
    let qualified = format!("binary-analysis/{rule_id}");
    BinaryAnalysisFinding {
        task_id: "binary-analysis".to_string(),
        fingerprint: fingerprint_for(ctx.repo_root, rule_id, ctx.rel_path),
        rule_id: qualified,
        file_path: ctx.rel_path.to_string(),
        format: format.to_string(),
        severity,
        message: message.to_string(),
        evidence: format!("{}: {evidence}", ctx.rel_path),
        cwe: cwe.iter().map(|s| (*s).to_string()).collect(),
    }
}

fn cwe_for_risky_import(name: &str) -> &[&'static str] {
    match name {
        "system" | "popen" | "WinExec" | "ShellExecute" | "ShellExecuteA" | "ShellExecuteW" => {
            &["CWE-78"]
        }
        "LoadLibrary" | "LoadLibraryA" | "LoadLibraryW" => &["CWE-114"],
        "MD5_Init" | "MD5_Update" | "MD5_Final" | "SHA1_Init" | "SHA1_Update" | "SHA1_Final"
        | "DES_set_key" | "RC4" => &["CWE-327"],
        _ => &["CWE-120"],
    }
}

// ---------------------------------------------------------------------------
// Byte readers (total over the buffer; return None on out-of-bounds)
// ---------------------------------------------------------------------------

fn read_u16(buf: &[u8], off: usize, little_endian: bool) -> Option<u16> {
    if little_endian {
        read_u16_le(buf, off)
    } else {
        read_u16_be(buf, off)
    }
}

fn read_u32(buf: &[u8], off: usize, little_endian: bool) -> Option<u32> {
    if little_endian {
        read_u32_le(buf, off)
    } else {
        read_u32_be(buf, off)
    }
}

fn read_u64(buf: &[u8], off: usize, little_endian: bool) -> Option<u64> {
    if little_endian {
        read_u64_le(buf, off)
    } else {
        read_u64_be(buf, off)
    }
}

fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(buf.get(off..off + 2)?.try_into().ok()?))
}

fn read_u16_be(buf: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes(buf.get(off..off + 2)?.try_into().ok()?))
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(buf.get(off..off + 4)?.try_into().ok()?))
}

fn read_u32_be(buf: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_be_bytes(buf.get(off..off + 4)?.try_into().ok()?))
}

fn read_u64_le(buf: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(buf.get(off..off + 8)?.try_into().ok()?))
}

fn read_u64_be(buf: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_be_bytes(buf.get(off..off + 8)?.try_into().ok()?))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn elf_header_64() -> Vec<u8> {
        // Minimal 64-bit little-endian ELF header (64 bytes) + one
        // PT_GNU_STACK program header with PF_X clear (NX = on).
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        buf[4] = 2; // 64-bit
        buf[5] = 1; // little-endian
        buf[16..18].copy_from_slice(&(ET_DYN).to_le_bytes()); // e_type = ET_DYN (PIE)
        buf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff = 64
        buf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        buf[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum = 1

        // Program header: PT_GNU_STACK
        let mut ph = vec![0u8; 56];
        ph[0..4].copy_from_slice(&PT_GNU_STACK.to_le_bytes());
        // p_flags at offset 4 for 64-bit phdr — leave 0 for NX = on.
        buf.extend(ph);
        buf
    }

    fn pe_header(opt_magic: u16, dll_char: u16) -> Vec<u8> {
        // DOS header at 0x00, e_lfanew at 0x3c, PE signature, COFF header,
        // optional header up through DllCharacteristics at +94.
        let pe_off: usize = 0x80;
        let mut buf = vec![0u8; pe_off + 24 + 96];
        buf[0..2].copy_from_slice(b"MZ");
        buf[0x3c..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        buf[pe_off..pe_off + 4].copy_from_slice(&[b'P', b'E', 0, 0]);
        buf[pe_off + 24..pe_off + 26].copy_from_slice(&opt_magic.to_le_bytes());
        let dll_off = pe_off + 24 + 70;
        buf[dll_off..dll_off + 2].copy_from_slice(&dll_char.to_le_bytes());
        buf
    }

    fn macho_header(magic: u32, flags: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 32];
        buf[0..4].copy_from_slice(&magic.to_le_bytes());
        let little_endian = matches!(magic, 0xfeed_face | 0xfeed_facf);
        if little_endian {
            buf[24..28].copy_from_slice(&flags.to_le_bytes());
        } else {
            buf[24..28].copy_from_slice(&flags.to_be_bytes());
        }
        buf
    }

    fn wasm_header(version: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(&[0x00, b'a', b's', b'm']);
        buf[4..8].copy_from_slice(&version.to_le_bytes());
        buf
    }

    #[test]
    fn identify_recognises_each_format() {
        assert_eq!(identify_binary(&elf_header_64()), Some(BinaryFormat::Elf));
        assert_eq!(
            identify_binary(&pe_header(0x10b, 0)),
            Some(BinaryFormat::Pe)
        );
        assert_eq!(
            identify_binary(&macho_header(0xfeed_facf, 0)),
            Some(BinaryFormat::Macho)
        );
        assert_eq!(
            identify_binary(&wasm_header(1)),
            Some(BinaryFormat::Wasm)
        );

        // Java class files share 0xCAFEBABE; we cap nfat <= 32 so a Java
        // major version like 65 (Java 21) reads as a too-large nfat and
        // identify_binary rejects it.
        let mut java_class = vec![0u8; 16];
        java_class[0..4].copy_from_slice(&0xcafe_babeu32.to_be_bytes());
        java_class[4..8].copy_from_slice(&65u32.to_be_bytes());
        assert_eq!(identify_binary(&java_class), None);

        // A genuine Mach-O FAT with nfat == 2 should still identify.
        let mut macho_fat = vec![0u8; 16];
        macho_fat[0..4].copy_from_slice(&0xcafe_babeu32.to_be_bytes());
        macho_fat[4..8].copy_from_slice(&2u32.to_be_bytes());
        assert_eq!(
            identify_binary(&macho_fat),
            Some(BinaryFormat::MachoFat)
        );

        // Random bytes — no match.
        assert_eq!(identify_binary(b"hello, world!"), None);
    }

    #[test]
    fn parse_elf_extracts_pie_and_nx_stack() {
        let info = parse_elf(&elf_header_64()).expect("parse");
        assert_eq!(info.bits, 64);
        assert!(info.little_endian);
        assert_eq!(info.e_type, ET_DYN);
        assert!(info.nx_stack);
        assert!(info.has_gnu_stack);
        assert!(!info.has_relro);
        assert!(!info.bind_now);
        assert!(!info.stack_canary);
    }

    #[test]
    fn check_elf_emits_expected_findings_for_minimal_binary() {
        let info = parse_elf(&elf_header_64()).expect("parse");
        let path = PathBuf::from("/tmp");
        let ctx = CheckCtx {
            repo_root: &path,
            rel_path: "bin/example",
        };
        let findings = check_elf(&info, &ctx);
        let rule_ids: BTreeSet<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        // PIE present (no missing-pie), no GNU_STACK header marker should
        // not fire because we emitted one. RELRO + canary should fire.
        assert!(rule_ids.contains("binary-analysis/elf-missing-relro"));
        assert!(rule_ids.contains("binary-analysis/elf-missing-stack-canary"));
        assert!(!rule_ids.contains("binary-analysis/elf-missing-pie"));
        assert!(!rule_ids.contains("binary-analysis/elf-executable-stack"));
    }

    #[test]
    fn parse_pe_extracts_dll_characteristics() {
        let buf = pe_header(0x20b, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT);
        let info = parse_pe(&buf).expect("parse");
        assert_eq!(info.bits, 64);
        assert!(info.aslr);
        assert!(info.dep);
        assert!(!info.cfg);
        assert!(!info.high_entropy_va);
    }

    #[test]
    fn check_pe_flags_missing_dep_and_aslr() {
        let buf = pe_header(0x10b, 0);
        let info = parse_pe(&buf).expect("parse");
        let path = PathBuf::from("/tmp");
        let ctx = CheckCtx {
            repo_root: &path,
            rel_path: "bin/win.exe",
        };
        let findings = check_pe(&info, &ctx);
        let rule_ids: BTreeSet<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rule_ids.contains("binary-analysis/pe-missing-aslr"));
        assert!(rule_ids.contains("binary-analysis/pe-missing-dep"));
        assert!(rule_ids.contains("binary-analysis/pe-missing-cfg"));
    }

    #[test]
    fn check_macho_flags_missing_pie() {
        let info = parse_macho(&macho_header(0xfeed_facf, 0)).expect("parse");
        let path = PathBuf::from("/tmp");
        let ctx = CheckCtx {
            repo_root: &path,
            rel_path: "bin/mac",
        };
        let findings = check_macho(&info, &ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "binary-analysis/macho-missing-pie");
        assert_eq!(findings[0].severity, BinarySeverity::Warning);
    }

    #[test]
    fn check_macho_passes_when_pie_set() {
        let info = parse_macho(&macho_header(0xfeed_facf, MH_PIE)).expect("parse");
        let path = PathBuf::from("/tmp");
        let ctx = CheckCtx {
            repo_root: &path,
            rel_path: "bin/mac-pie",
        };
        let findings = check_macho(&info, &ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn check_wasm_only_flags_unexpected_version() {
        let path = PathBuf::from("/tmp");
        let ctx = CheckCtx {
            repo_root: &path,
            rel_path: "module.wasm",
        };
        assert!(check_wasm(&WasmInfo { version: 1 }, &ctx).is_empty());
        let bad = check_wasm(&WasmInfo { version: 99 }, &ctx);
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0].rule_id, "binary-analysis/wasm-unexpected-version");
    }

    #[test]
    fn nul_anchored_match_rejects_substring_of_longer_symbol() {
        // "mystrcpy\0" contains "strcpy" but the leading char is 'y', not
        // a NUL — so the anchored matcher must not match.
        let buf = b"\0mystrcpy\0other\0";
        assert!(!contains_nul_anchored(buf, b"strcpy"));
        // A real strcpy import surrounded by NULs must match.
        let buf = b"\0strcpy\0foo\0";
        assert!(contains_nul_anchored(buf, b"strcpy"));
    }

    #[test]
    fn binary_severity_round_trips() {
        for &sev in &[
            BinarySeverity::Error,
            BinarySeverity::Warning,
            BinarySeverity::Info,
        ] {
            let s = sev.as_str();
            assert_eq!(BinarySeverity::try_from(s).unwrap(), sev);
        }
        assert!(BinarySeverity::try_from("DEFCON-1").is_err());
    }

    #[test]
    fn options_from_tool_input_parses_all_fields() {
        let input = json!({
            "maxFileBytes": 16_000,
            "maxFindings": 5,
            "excludeDirs": ["custom-vendor"],
            "severity": ["ERROR", "INFO"],
        });
        let opts = BinaryAnalysisOptions::from_tool_input(&input).unwrap();
        assert_eq!(opts.max_file_bytes, 16_000);
        assert_eq!(opts.max_findings, 5);
        assert!(opts.exclude_dirs.contains("custom-vendor"));
        let severities = opts.severity.unwrap();
        assert!(severities.contains(&BinarySeverity::Error));
        assert!(severities.contains(&BinarySeverity::Info));
        assert!(!severities.contains(&BinarySeverity::Warning));
    }

    #[test]
    fn options_clamp_pathological_inputs() {
        let opts = BinaryAnalysisOptions::from_tool_input(&json!({
            "maxFileBytes": 1,
            "maxFindings": 99_999,
        }))
        .unwrap();
        assert_eq!(opts.max_file_bytes, 1024);
        assert_eq!(opts.max_findings, 10_000);
    }

    #[test]
    fn scan_binaries_walks_tempdir_and_finds_elf_findings() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("bin")).unwrap();
        fs::write(temp.path().join("bin/example"), elf_header_64()).unwrap();
        fs::write(temp.path().join("README.md"), "not a binary").unwrap();
        // node_modules is in the default exclude list — anything under it
        // must be skipped even if it looks like an ELF.
        fs::create_dir(temp.path().join("node_modules")).unwrap();
        fs::write(
            temp.path().join("node_modules/hidden"),
            elf_header_64(),
        )
        .unwrap();

        let report = scan_binaries(
            temp.path(),
            &BinaryAnalysisOptions::default(),
            &ScanCancellation::default(),
        )
        .unwrap();

        assert_eq!(report.binaries_identified, 1);
        let rule_ids: BTreeSet<_> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rule_ids.contains("binary-analysis/elf-missing-relro"));
        // Findings are scoped to the identified binary, not the README.
        assert!(report
            .findings
            .iter()
            .all(|f| f.file_path == "bin/example"));
    }

    #[test]
    fn scan_binaries_respects_max_findings() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("a"), elf_header_64()).unwrap();
        fs::write(temp.path().join("b"), elf_header_64()).unwrap();
        let opts = BinaryAnalysisOptions {
            max_findings: 2,
            ..BinaryAnalysisOptions::default()
        };
        let report =
            scan_binaries(temp.path(), &opts, &ScanCancellation::default()).unwrap();
        assert_eq!(report.findings.len(), 2);
    }

    #[test]
    fn scan_binaries_severity_filter_drops_other_levels() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("a"), elf_header_64()).unwrap();
        let mut severities = BTreeSet::new();
        severities.insert(BinarySeverity::Info);
        let opts = BinaryAnalysisOptions {
            severity: Some(severities),
            ..BinaryAnalysisOptions::default()
        };
        let report =
            scan_binaries(temp.path(), &opts, &ScanCancellation::default()).unwrap();
        assert!(report
            .findings
            .iter()
            .all(|f| f.severity == BinarySeverity::Info));
    }

    #[test]
    fn scan_binaries_rejects_non_directory_target() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("a");
        fs::write(&file, elf_header_64()).unwrap();
        let result = scan_binaries(
            &file,
            &BinaryAnalysisOptions::default(),
            &ScanCancellation::default(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn fingerprints_are_stable_across_runs() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("a"), elf_header_64()).unwrap();
        let report_a = scan_binaries(
            temp.path(),
            &BinaryAnalysisOptions::default(),
            &ScanCancellation::default(),
        )
        .unwrap();
        let report_b = scan_binaries(
            temp.path(),
            &BinaryAnalysisOptions::default(),
            &ScanCancellation::default(),
        )
        .unwrap();
        let fps_a: Vec<_> = report_a.findings.iter().map(|f| &f.fingerprint).collect();
        let fps_b: Vec<_> = report_b.findings.iter().map(|f| &f.fingerprint).collect();
        assert_eq!(fps_a, fps_b);
        assert!(fps_a.iter().all(|fp| fp.starts_with("binary-analysis:")));
    }

    #[test]
    fn report_to_tool_json_shape_matches_secret_scan_convention() {
        let report = BinaryAnalysisReport {
            target: "/tmp".to_string(),
            findings: vec![],
            files_scanned: 3,
            files_skipped: 1,
            binaries_identified: 0,
        };
        let value = report.to_tool_json();
        assert_eq!(value["ok"], json!(true));
        assert!(value["output"].as_str().unwrap().contains("binary-analysis"));
        assert_eq!(value["data"]["filesScanned"], json!(3));
        assert_eq!(value["data"]["filesSkipped"], json!(1));
        assert_eq!(value["data"]["binariesIdentified"], json!(0));
    }

    #[test]
    fn finding_to_core_finding_uses_binary_analysis_tool_id() {
        let finding = BinaryAnalysisFinding {
            task_id: "binary-analysis".to_string(),
            fingerprint: "binary-analysis:elf-missing-relro:abc".to_string(),
            rule_id: "binary-analysis/elf-missing-relro".to_string(),
            file_path: "bin/example".to_string(),
            format: "elf".to_string(),
            severity: BinarySeverity::Warning,
            message: "RELRO missing.".to_string(),
            evidence: "bin/example: no PT_GNU_RELRO".to_string(),
            cwe: vec!["CWE-1037".to_string()],
        };
        let core = finding.to_core_finding();
        assert_eq!(core.tool, "binary-analysis");
        assert_eq!(core.severity, Severity::Medium);
        assert_eq!(core.fingerprint, finding.fingerprint);
        assert_eq!(core.title, finding.message);
    }
}
