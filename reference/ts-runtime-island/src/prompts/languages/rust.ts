// NOTE: This file contains DETECTION PATTERNS for a security scanner.
// The API references are DETECTION TARGETS describing what the scanner
// looks for in scanned codebases, not code this file executes.

import type { LanguageProfile } from "./types.js";

export const rustProfile: LanguageProfile = {
  languageId: "Rust",
  aliases: ["rust", "rs"],
  generalHints: {
    grepPatterns: [
      "unsafe\\s*\\{",
      'extern\\s+"C"',
      "\\.unwrap\\(",
      "panic!\\(",
      "#\\[no_mangle\\]",
      "std::process::Command",
    ],
    fileHints: [
      "Cargo.toml for dependencies and features",
      "src/main.rs or src/lib.rs for entry points",
      "build.rs for build-time code generation and FFI bindings",
      "Files with 'unsafe' blocks",
    ],
    instructions: [
      "Check Cargo.toml for known vulnerable crate versions (cargo audit)",
      "Focus on unsafe blocks — Rust's safety guarantees do not apply inside them",
      "Check FFI boundaries — data crossing into/from C code needs manual validation",
      "Look for .unwrap() on user-controlled Results — can panic and crash the service",
    ],
  },
  generalAntiHallucination: [
    "Safe Rust prevents buffer overflows, use-after-free, and data races at compile time — only flag these inside unsafe blocks",
    "Rust's borrow checker prevents most memory safety issues — do NOT flag safe Rust code for memory bugs",
    "serde JSON/TOML/YAML deserialization is SAFE by default — it does not execute code",
  ],
  vulnClasses: {
    "unsafe-blocks": {
      sinks: [
        {
          api: "unsafe { ptr::read/write }",
          risk: "Manual pointer operations bypass borrow checker — UB if pointer is invalid",
          cwes: ["CWE-787", "CWE-416"],
        },
        {
          api: "unsafe { slice::from_raw_parts }",
          risk: "Creating slice from raw pointer — UB if length is wrong or ptr is invalid",
          cwes: ["CWE-120"],
        },
        {
          api: "unsafe { transmute }",
          risk: "Reinterprets bits as different type — UB if invariants violated",
          cwes: ["CWE-843"],
        },
        {
          api: "unsafe impl Send/Sync",
          risk: "Manual Send/Sync impl can enable data races if invariants are wrong",
          cwes: ["CWE-362"],
        },
      ],
      safePatterns: [
        {
          api: "unsafe in well-audited FFI wrapper with validation",
          why: "FFI requires unsafe but wrapper validates inputs",
        },
        {
          api: "unsafe for performance with documented invariants",
          why: "Acceptable if invariants are proven and tested",
        },
      ],
      investigationHints: {
        grepPatterns: [
          "unsafe\\s*\\{",
          "transmute",
          "from_raw_parts",
          "ptr::",
          "as\\s*\\*const",
          "as\\s*\\*mut",
        ],
        fileHints: [
          "FFI binding modules",
          "Performance-critical inner loops",
          "Custom allocator implementations",
        ],
        instructions: [
          "For each unsafe block, identify what invariant must hold and whether it can be violated by external input",
          "Check slice::from_raw_parts — is the length from a trusted source? Can an attacker control it?",
          "Look for unsafe impl Send for types containing raw pointers — is concurrent access actually safe?",
          "Check transmute calls — does the source type actually have the same layout as the target?",
        ],
      },
      fewShots: [
        {
          scenario: "Unsafe slice creation with attacker-controlled length",
          vulnerableCode:
            "fn parse_packet(data: &[u8]) -> &[u32] {\n    let len = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;\n    unsafe { std::slice::from_raw_parts(data[4..].as_ptr() as *const u32, len) }\n}",
          explanation:
            "len comes from the packet (attacker-controlled). If len exceeds the actual data size, from_raw_parts creates an out-of-bounds slice — reading arbitrary memory.",
        },
      ],
      antiHallucinationExtra: [
        "Safe Rust code (no unsafe keyword) CANNOT have buffer overflows or use-after-free — do NOT flag it",
        "Unsafe blocks for calling well-known C libraries (libc, OpenSSL bindings) with correct signatures are generally safe",
      ],
    },
    "ffi-boundary": {
      sinks: [
        {
          api: 'extern "C" fn receiving *const/*mut',
          risk: "C code may pass invalid pointers — Rust code must validate before deref",
          cwes: ["CWE-476", "CWE-787"],
        },
        {
          api: "CString::from_raw(ptr)",
          risk: "Takes ownership of C-allocated string — double free if C also frees it",
          cwes: ["CWE-415"],
        },
        {
          api: "Box::from_raw(ptr)",
          risk: "Takes ownership — UB if ptr was not from Box::into_raw",
          cwes: ["CWE-416"],
        },
      ],
      safePatterns: [
        {
          api: "CStr::from_ptr(ptr) for borrowed access",
          why: "Borrows without taking ownership — C retains ownership",
        },
        { api: "Null check before deref", why: "Prevents null pointer dereference from C callers" },
      ],
      investigationHints: {
        grepPatterns: [
          'extern\\s+"C"',
          "#\\[no_mangle\\]",
          "CString",
          "CStr",
          "Box::from_raw",
          "from_raw_parts",
        ],
        fileHints: [
          "FFI modules (ffi.rs, bindings.rs, sys/)",
          "build.rs for bindgen usage",
          "C header files (.h) that define the FFI interface",
        ],
        instructions: [
          "Check every extern function — are pointer parameters validated for null before use?",
          "Look for ownership confusion: does Rust take ownership (Box::from_raw) of memory C will also free?",
          "Check lifetime assumptions — does Rust hold references to C-allocated memory that C may free?",
        ],
      },
      fewShots: [
        {
          scenario: "FFI callback with null pointer dereference",
          vulnerableCode:
            '#[no_mangle]\npub extern "C" fn process_buffer(ptr: *const u8, len: usize) -> i32 {\n    let data = unsafe { std::slice::from_raw_parts(ptr, len) };\n    // ...\n}',
          explanation:
            "C caller may pass null ptr. from_raw_parts with null pointer is immediate UB. Must check ptr.is_null() before creating the slice.",
        },
      ],
      antiHallucinationExtra: [
        "FFI unsafe blocks are EXPECTED in Rust — the question is whether inputs are validated, not whether unsafe exists",
      ],
    },
    "command-injection": {
      sinks: [
        {
          api: 'std::process::Command::new("sh").arg("-c").arg(user_str)',
          risk: "Shell interpretation of user-controlled string",
          shellInvoking: true,
          cwes: ["CWE-78"],
        },
        {
          api: "std::process::Command::new(user_binary)",
          risk: "User controls which binary is executed",
          shellInvoking: false,
          cwes: ["CWE-78"],
        },
      ],
      safePatterns: [
        {
          api: 'Command::new("fixed-binary").arg(user_arg)',
          why: "Fixed binary with user args — no shell involved",
        },
      ],
      investigationHints: {
        grepPatterns: ["Command::new\\(", "\\.arg\\(", "\\.args\\("],
        fileHints: ["Process spawning utilities", "Build/CI helpers"],
        instructions: [
          'Check if Command::new uses "sh" or "bash" with "-c" — this enables shell interpretation',
          'Command::new("fixed").arg(user_input) is safe against shell injection (no shell involved)',
        ],
      },
      fewShots: [
        {
          scenario: "Shell command with user-controlled argument",
          vulnerableCode:
            'let output = Command::new("sh")\n    .arg("-c")\n    .arg(format!("ffmpeg -i {} output.mp4", user_filename))\n    .output()?;',
          explanation:
            "user_filename is interpolated into a shell command string. Attacker sends 'input.mp4; rm -rf /' — shell interprets the semicolon.",
        },
      ],
      antiHallucinationExtra: [
        'Command::new("binary").arg(user_input) without shell is NOT vulnerable to shell metachar injection',
      ],
    },
  },
};
