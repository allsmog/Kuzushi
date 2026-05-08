import type { KnowledgeModule } from "../types.js";

/**
 * Parser attack-surface patterns — the vocabulary that fuzz-forge uses to
 * rank targets and prime the LLM when generating harnesses.
 *
 * Focus: native/binary parsers, decoders, deserializers, and wire-protocol
 * state machines. These are the shapes the workers.io Brotli analysis and
 * the broader memory-safety CVE corpus keep rediscovering.
 */
export const parserAttackSurfaceModule: KnowledgeModule = {
  id: "parser-attack-surface",
  cwes: [
    "CWE-20",
    "CWE-125",
    "CWE-190",
    "CWE-191",
    "CWE-369",
    "CWE-416",
    "CWE-476",
    "CWE-617",
    "CWE-674",
    "CWE-787",
    "CWE-120",
    "CWE-131",
    "CWE-400",
  ],
  languages: ["c", "cpp", "rust", "go", "zig"],
  frameworks: [],
  dangerousPatterns: [
    {
      pattern: "memcpy / memmove with attacker-controlled length",
      why: "Classic OOB write primitive — Brotli-class bug. Length must be bounds-checked against destination capacity.",
      severity: "ERROR",
    },
    {
      pattern: "Signed/unsigned mixing in length arithmetic",
      why: "Negative length becomes huge unsigned value after promotion; passes naive `if (len <= cap)` checks.",
      severity: "ERROR",
    },
    {
      pattern: "Custom varint / LEB128 / elias decoder without bound",
      why: "Varint loops that accumulate into a fixed-width integer overflow when attacker sends many continuation bytes.",
      severity: "ERROR",
    },
    {
      pattern: "Length field from untrusted header used for allocation size",
      why: "Direct `malloc(header.len)` trusts attacker — must check against ceiling + overflow.",
      severity: "ERROR",
    },
    {
      pattern: "Window / block size trusted without validation",
      why: "Compression/encoding formats (Brotli, zlib, zstd) carry window-size fields — trusting them unchecked is the Brotli CVE pattern.",
      severity: "ERROR",
    },
    {
      pattern: "Recursive descent parser without depth limit",
      why: "Attacker-controlled nesting triggers stack overflow (CWE-674). All XML/JSON/protobuf parsers need a depth cap.",
      severity: "ERROR",
    },
    {
      pattern: "State-machine transition without input validation",
      why: "Wire protocol parsers that advance state on attacker-controlled opcodes often skip invariants, reaching unexpected states.",
      severity: "WARNING",
    },
    {
      pattern: "Integer multiplication for allocation without overflow check",
      why: "`malloc(count * sizeof(T))` — classic wrap-around into a small allocation followed by OOB write.",
      severity: "ERROR",
    },
    {
      pattern: "Pointer arithmetic using attacker-controlled offset",
      why: "`ptr += user_offset` with no upper bound yields an arbitrary read/write primitive.",
      severity: "ERROR",
    },
    {
      pattern: "Double-free or use-after-free on parse error path",
      why: "Cleanup code that runs on malformed input often double-frees or leaves dangling references.",
      severity: "ERROR",
    },
    {
      pattern: "Null-pointer dereference on optional parse field",
      why: "Parsers that assume an optional field is present after a partial-parse branch crash on crafted input (DoS, sometimes exploitable).",
      severity: "WARNING",
    },
    {
      pattern: "Format string derived from untrusted input",
      why: "`printf(user_data)` remains a leak/write primitive in C/C++ parsers that log field contents.",
      severity: "ERROR",
    },
    {
      pattern: "Missing canary / sentinel check on decoded stream end",
      why: "Decoders that don't verify stream termination can read past the buffer (OOB read) or mis-align subsequent frames.",
      severity: "WARNING",
    },
  ],
  safePatterns: [
    {
      pattern: "Checked allocation: `if (count > MAX || count > SIZE_MAX / sizeof(T)) return ERR;`",
      why: "Prevents integer overflow in allocation math before it happens.",
    },
    {
      pattern: "Bounds-checked memcpy via `memcpy_s` / `copy_to_user` with explicit cap",
      why: "Forces the copy to fail noisily instead of writing past the destination.",
    },
    {
      pattern: "Depth-counted recursive parser (depth argument threaded through each call)",
      why: "Caps nesting before stack exhaustion.",
    },
    {
      pattern: "Varint decoder with explicit max-bytes ceiling",
      why: "Rejects pathological inputs before accumulator overflow.",
    },
    {
      pattern: "`size_t` everywhere for sizes/offsets; checked conversions at I/O boundary",
      why: "Eliminates the signed/unsigned mixing class entirely.",
    },
  ],
  bypassTechniques: [
    "Very large length fields often bypass 16-bit or 32-bit check variables; try sizes near and past 2^31 and 2^32.",
    "Zero-length and negative-length edges can skip allocation paths and still reach copy sinks.",
    "Nested allocations: the outer length checks out but an inner field overflows the derived size.",
    "Trailing garbage after a valid frame often reaches a second parse path that lacks the same guards.",
    "Repeated-field denial-of-service: millions of tiny valid records exhaust allocator and trigger overflow in counters.",
    "Unicode / multibyte boundary confusion in text-formatted parsers (JSON, YAML) reaches byte-level sinks the char-level logic assumed safe.",
  ],
  detectionKeywords: [
    "memcpy",
    "memmove",
    "memset",
    "strcpy",
    "strncpy",
    "strcat",
    "sprintf",
    "snprintf",
    "malloc",
    "realloc",
    "calloc",
    "alloca",
    "read",
    "write",
    "varint",
    "leb128",
    "decode",
    "encode",
    "parse",
    "deserialize",
    "unmarshal",
    "length",
    "len",
    "size",
    "count",
    "capacity",
    "offset",
    "window",
    "block_size",
    "depth",
    "recursion",
    "state_transition",
    "opcode",
    "frame",
    "packet",
    "header",
  ],
  fixExamples: [
    {
      language: "c",
      before: "memcpy(dst, src, header.length);",
      after:
        "if (header.length > sizeof(dst) || header.length > src_remaining) return -EINVAL;\nmemcpy(dst, src, header.length);",
      explanation: "Bound the copy against both destination capacity and remaining source bytes.",
    },
    {
      language: "c",
      before: "size_t total = count * sizeof(T);\nvoid *p = malloc(total);",
      after:
        "size_t total;\nif (__builtin_mul_overflow(count, sizeof(T), &total)) return NULL;\nvoid *p = malloc(total);",
      explanation:
        "Detect multiplication wrap-around before allocation. The textbook CVE fix shape.",
    },
    {
      language: "cpp",
      before: "int len = read_varint(in);\nbuf.resize(len);",
      after:
        "int64_t len = read_varint(in);\nif (len < 0 || len > kMaxFrameSize) return Status::InvalidArgument;\nbuf.resize(static_cast<size_t>(len));",
      explanation:
        "Signed width for varint accumulator + explicit ceiling prevents both negative and huge-length attacks.",
    },
    {
      language: "rust",
      before: "let buf = vec![0u8; header.len as usize];",
      after:
        "let len = header.len as usize;\nif len > MAX_FRAME { return Err(Error::OversizedFrame); }\nlet buf = vec![0u8; len];",
      explanation:
        "Even memory-safe languages still need a ceiling — otherwise this is a DoS vector.",
    },
  ],
  tags: [
    "fuzzing",
    "parser",
    "decoder",
    "deserializer",
    "memory-safety",
    "attack-surface",
    "wire-protocol",
    "native",
  ],
};
