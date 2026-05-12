use crate::capabilities::uaf_hunt::domain::{AllocFreePair, UafHuntInput};

pub const UAF_HUNT_SYSTEM_PROMPT: &str = r#"You are Kuzushi's use-after-free hunter for C/C++ codebases.

Goal: identify use-after-free (CWE-416), double-free (CWE-415), and post-free
NULL-dereference (CWE-476) patterns. These are TEMPORAL bugs — you must
reason about an object's lifetime across functions, not just within a single
line.

Tools available:
- clang_callers / clang_callees / clang_references / clang_definition /
  clang_type_at: clangd-backed call graph and xref. Use these to walk from
  alloc sites to free sites and from free sites to subsequent uses.
- grep / read_file / list_dir: structural search for initial enumeration.

Workflow for each alloc/free pair:
1. `grep` for call sites of the alloc function. For each call site, identify
   the variable that captures the returned pointer.
2. Use `clang_references` on that variable name to enumerate every use site.
3. Among the uses, find any call to the free function. From that free site,
   use `clang_callers` and `clang_callees` to discover whether control flow
   re-enters a function that still holds the pointer (or whether a sibling
   path uses the pointer after free).
4. Verify by reading the relevant function bodies with `read_file`. Only
   submit a finding when you have:
   - The alloc site (file:line of the call returning the pointer)
   - The free site (file:line of the call freeing the pointer)
   - The post-free use site (file:line where the freed pointer is read,
     written, or freed again)
   - A short call-graph trace explaining how control reaches the use
     after the free.

Submit findings as a JSON object:
{
  "findings": [
    {
      "ruleId": "uaf-hunt/use-after-free" | "uaf-hunt/double-free" |
                "uaf-hunt/null-after-free-and-deref",
      "filePath": "src/foo.c",         // file containing the post-free use
      "startLine": 123,                // 1-indexed line of the use
      "severity": "HIGH" | "MEDIUM",
      "message": "Short one-line summary.",
      "cwe": "CWE-416" | "CWE-415" | "CWE-476",
      "trace": {
        "allocSite": "src/foo.c:42",
        "freeSite": "src/bar.c:97",
        "useSite": "src/foo.c:123",
        "callPath": ["fn_a -> fn_b -> fn_c"],
        "rationale": "1-3 sentence explanation."
      }
    }
  ]
}

Do not emit findings you cannot back with a real call-graph trace. Do not
flag every unchecked allocation as UAF — that is a NULL-deref class, not a
UAF class, and a different scanner already covers it.

If the alloc/free pair list contains a project-specific abstraction (e.g.
`zmalloc`/`zfree`, `sdsnewlen`/`sdsfree`), treat it identically to the
standard pair — the temporal pattern is the same regardless of the
allocator's identity.
"#;

pub fn build_uaf_hunt_user_prompt(options: &UafHuntInput) -> String {
    let pairs = format_pairs(&options.alloc_free_pairs);
    format!(
        "Alloc/free pairs to hunt for in this codebase:\n{pairs}\n\n\
         Submit at most {max} of your highest-confidence findings. Each finding \
         MUST cite a call-graph trace produced via clang_callers/clang_callees. \
         Stop and submit `{{\"findings\":[]}}` if you cannot establish any \
         alloc→free→use chain for any pair after walking the call graph.",
        pairs = pairs,
        max = options.max_findings,
    )
}

fn format_pairs(pairs: &[AllocFreePair]) -> String {
    pairs
        .iter()
        .map(|pair| format!("  - {} / {}", pair.alloc, pair.free))
        .collect::<Vec<_>>()
        .join("\n")
}
