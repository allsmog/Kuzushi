//! Per-language hunt-hint catalogs injected into finding-producing prompts.
//!
//! Where `validator_catalogs` tells verifiers which upstream guards to look
//! for before clearing a finding, these hints tell hunters which bug shapes
//! to start from in each language. Hints are investigation starting points,
//! not checklists — prompts frame them as "explore beyond these".

use super::validator_catalogs::PromptLanguage;

pub const C_CPP_HUNT_HINTS: &str =
    "C/C++ investigation starting points (explore beyond these):
- malloc/calloc/realloc size arguments that can overflow or wrap;
- memcpy/memmove/strncpy/sprintf lengths not bounded by the destination buffer;
- signed/unsigned casts in bounds checks; signed length compared against unsigned capacity;
- double-free via error-handling paths (partial init -> cleanup frees -> caller frees again), \
shallow struct copies aliasing internal pointers, pointer-arithmetic frees (freeing an \
advanced pointer), the same pointer freed on both the success path and a shared cleanup/goto \
label, and retry loops that free inside the loop body then continue with the dangling pointer;
- integer overflow in size multiplication (width * height * bpp) producing undersized \
allocations;
- unsigned subtraction wrap (len - header_size when len < header_size) and indexing \
buf[len - N] without checking len >= N;
- trusted length/size fields read from files or the network and used directly for reads or \
copies without capping to buffer capacity;
- bounds checks that test the WRONG variable or use the wrong comparison — the check exists \
but is wrong;
- off-by-one in parser loops (< vs <=) and wrong hardcoded byte counts in memcpy/memset \
(off-by-constant, not off-by-one);
- use-after-free via cached references to objects freed elsewhere.";

pub const RUST_HUNT_HINTS: &str = "Rust investigation starting points (explore beyond these):
- unsafe blocks whose documented safety invariants are not actually enforced;
- Send/Sync impls on types with interior mutability or raw pointers;
- FFI boundaries where pointer lifetimes are not tracked across the boundary;
- transmute, from_raw_parts, and pointer arithmetic — verify the safety conditions;
- safe public APIs wrapping unsafe internals where a caller-visible call order creates \
dangling references (get_ref then reset).";

pub const GO_HUNT_HINTS: &str = "Go investigation starting points (explore beyond these):
- text/template used where html/template is required for user content;
- shared state accessed from goroutines without synchronization;
- unchecked type assertions (x.(Type) without the , ok pattern);
- TOCTOU in file operations (stat then open, check then use);
- path traversal through filepath.Join with user input.";

pub const TYPESCRIPT_HUNT_HINTS: &str =
    "JavaScript/TypeScript investigation starting points (explore beyond these):
- prototype pollution: obj[userKey] = value, deep merge/extend with user objects;
- regexes on user input with catastrophic backtracking potential (ReDoS);
- innerHTML or template literals inserting user content without escaping;
- command injection via child_process with user-influenced arguments;
- path traversal in file-serving or static-file middleware.";

pub const PYTHON_HUNT_HINTS: &str = "Python investigation starting points (explore beyond these):
- unsafe deserialization of untrusted input (yaml.load without SafeLoader, pickle);
- ORM escape hatches: .raw(), .extra(), f-string/format query construction;
- template rendering that bypasses auto-escaping (mark_safe, |safe, Markup());
- subprocess/os.system/os.popen with user-controlled arguments.";

pub const JAVA_HUNT_HINTS: &str =
    "Java/Kotlin investigation starting points (explore beyond these):
- ObjectInputStream deserialization without type filtering; polymorphic deserialization \
(Jackson/Gson) with missing or incomplete type allowlists;
- XML parsers (DocumentBuilderFactory, SAXParserFactory) with external entities enabled;
- JNDI lookups and expression-language evaluation (Spring EL, OGNL, MVEL) with \
user-influenced input;
- Runtime.exec/ProcessBuilder with user-influenced arguments;
- SQL built via string templates/concatenation instead of bound parameters.";

/// Hunt hints for one language group; `Other` has none.
pub fn hunt_hints_for_language(language: PromptLanguage) -> &'static str {
    match language {
        PromptLanguage::CorCpp => C_CPP_HUNT_HINTS,
        PromptLanguage::Rust => RUST_HUNT_HINTS,
        PromptLanguage::Go => GO_HUNT_HINTS,
        PromptLanguage::TypeScript => TYPESCRIPT_HUNT_HINTS,
        PromptLanguage::Python => PYTHON_HUNT_HINTS,
        PromptLanguage::JavaSpring => JAVA_HUNT_HINTS,
        PromptLanguage::Other => "",
    }
}

/// Combine hunt hints for the language groups present in `paths`, in a fixed
/// canonical order. Returns `None` when no group with hints is present.
pub fn hunt_hints_for_paths<'a>(paths: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let present: Vec<PromptLanguage> = paths
        .into_iter()
        .map(PromptLanguage::from_path)
        .collect();
    let ordered = [
        PromptLanguage::CorCpp,
        PromptLanguage::Rust,
        PromptLanguage::Go,
        PromptLanguage::TypeScript,
        PromptLanguage::Python,
        PromptLanguage::JavaSpring,
    ];
    let blocks: Vec<&str> = ordered
        .into_iter()
        .filter(|language| present.contains(language))
        .map(hunt_hints_for_language)
        .filter(|hints| !hints.is_empty())
        .collect();
    if blocks.is_empty() {
        None
    } else {
        Some(blocks.join("\n\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_paths_select_the_memory_safety_hints() {
        let hints = hunt_hints_for_paths(["src/parser.c", "src/util.h"]).unwrap();
        assert!(hints.contains("unsigned subtraction wrap"));
        assert!(!hints.contains("prototype pollution"));
    }

    #[test]
    fn mixed_paths_combine_in_canonical_order() {
        let hints = hunt_hints_for_paths(["a.py", "b.c", "c.ts"]).unwrap();
        let c_at = hints.find("C/C++ investigation").unwrap();
        let ts_at = hints.find("JavaScript/TypeScript investigation").unwrap();
        let py_at = hints.find("Python investigation").unwrap();
        assert!(c_at < ts_at && ts_at < py_at);
    }

    #[test]
    fn unknown_extensions_produce_no_hints() {
        assert!(hunt_hints_for_paths(["README.md", "notes.txt"]).is_none());
    }
}
