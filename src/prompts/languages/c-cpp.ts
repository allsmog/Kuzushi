import type { LanguageProfile } from "./types.js";

export const cCppProfile: LanguageProfile = {
  languageId: "C/C++",
  aliases: ["c", "cpp", "cxx", "c++", "cc"],
  generalHints: {
    grepPatterns: [
      "#define.*_SIZE",
      "#define.*_LEN",
      "#define.*MAX",
      "#define.*BUF",
      "memcpy\\(",
      "memmove\\(",
      "malloc\\(",
      "free\\(",
    ],
    fileHints: [
      "Header files (.h) for buffer size constants and struct layouts",
      "Makefile / CMakeLists.txt for compiler flags (-fstack-protector, ASAN)",
      "configure.ac for feature flags that toggle code paths",
    ],
    instructions: [
      "Always grep for #define values that set buffer sizes and resolve them to numeric values before judging bounds checks",
      "Check struct layouts for packed attributes and padding that affect sizeof calculations",
      "Look for compiler-specific extensions (__attribute__, __builtin_) that affect safety guarantees",
    ],
  },
  generalAntiHallucination: [
    "A named constant is NOT a verified bound — grep for its #define and resolve the numeric value",
    "Do NOT assume a function is safe based on its name; verify the implementation",
    "sizeof(struct) may differ from sum of fields due to alignment padding",
  ],
  vulnClasses: {
    "buffer-overflow": {
      sinks: [
        {
          api: "memcpy(dst, src, len)",
          risk: "Copies len bytes without checking dst capacity",
          cwes: ["CWE-120", "CWE-787"],
        },
        {
          api: "memmove(dst, src, len)",
          risk: "Same risk as memcpy — no bounds check on dst",
          cwes: ["CWE-120"],
        },
        {
          api: "strcpy(dst, src)",
          risk: "Copies until NUL with no length limit",
          cwes: ["CWE-120"],
        },
        {
          api: "strcat(dst, src)",
          risk: "Appends without checking remaining dst capacity",
          cwes: ["CWE-120"],
        },
        {
          api: "sprintf(buf, fmt, ...)",
          risk: "Formats into buf with no size limit",
          cwes: ["CWE-120"],
        },
        {
          api: "gets(buf)",
          risk: "Reads from stdin until newline with no buffer limit",
          cwes: ["CWE-120"],
        },
        {
          api: "sscanf with %s",
          risk: "Reads unbounded string into fixed buffer",
          cwes: ["CWE-120"],
        },
        {
          api: "read/recv into fixed buffer",
          risk: "Network/file reads with attacker-controlled length",
          cwes: ["CWE-120"],
        },
      ],
      safePatterns: [
        {
          api: "strncpy(dst, src, sizeof(dst))",
          why: "Bounded copy — but check for NUL termination",
        },
        {
          api: "snprintf(buf, sizeof(buf), ...)",
          why: "Bounded format — safe if size arg is correct",
        },
        { api: "strlcpy/strlcat", why: "BSD bounded string functions (if available)" },
        {
          api: "memcpy with static src and known len",
          why: "Hardcoded lengths with no attacker control are safe",
        },
      ],
      investigationHints: {
        grepPatterns: [
          "memcpy\\(",
          "strcpy\\(",
          "sprintf\\(",
          "strcat\\(",
          "gets\\(",
          "#define.*_SIZE",
          "#define.*_LEN",
          "#define.*_MAX",
          "#define.*BUF",
        ],
        fileHints: [
          "Packet parsing functions (parse_, handle_, process_)",
          "Header files for buffer size #defines and struct definitions",
          "Network/protocol handling code",
        ],
        instructions: [
          "For every memcpy/memmove: identify the destination buffer size (grep for its #define), identify the source of the length argument, and check if len <= dst_size is enforced",
          "Check if attacker-controlled length fields from packet headers or protocol messages reach copy operations",
          "Look for signed/unsigned comparison mismatches in length checks (int vs size_t)",
          "Check stack-allocated buffers in functions that parse untrusted input",
          "Inspect struct fields used as buffer sizes — are they validated after deserialization?",
        ],
      },
      fewShots: [
        {
          scenario: "Network packet parsing with unchecked length",
          vulnerableCode:
            "uint16_t opt_len = ntohs(hdr->length);\nchar buf[256];\nmemcpy(buf, hdr->data, opt_len);",
          explanation:
            "Attacker controls hdr->length via network packet. opt_len can exceed 256 (buf size). No bounds check before memcpy — stack buffer overflow.",
        },
        {
          scenario: "XDR deserialization with signed/unsigned mismatch",
          vulnerableCode:
            "int len = xdr_getint(xdr);\nif (len > MAX_NAME) return -1;\nchar name[MAX_NAME];\nmemcpy(name, xdr_getbytes(xdr), len);",
          explanation:
            "len is signed int. A negative value passes the > MAX_NAME check but wraps to a huge unsigned value in memcpy's size_t parameter — massive overflow.",
        },
      ],
      antiHallucinationExtra: [
        "A size check like 'if (len > BUF_SIZE)' is NOT sufficient if len is signed — negative values pass the check",
        "memcpy with hardcoded lengths and no attacker-controlled path is NOT a vulnerability",
        "sizeof(ptr) returns pointer size (4/8), not the allocation size — check for this mistake",
      ],
    },
    "integer-overflow": {
      sinks: [
        {
          api: "malloc(n * size)",
          risk: "Multiplication can wrap to small value, leading to undersized allocation",
          cwes: ["CWE-190"],
        },
        {
          api: "len1 + len2 used as allocation size",
          risk: "Addition overflow wraps to small value",
          cwes: ["CWE-190"],
        },
        {
          api: "signed int used as array index or size",
          risk: "Negative values bypass upper-bound checks",
          cwes: ["CWE-190", "CWE-681"],
        },
        {
          api: "ntohs/ntohl results used in arithmetic",
          risk: "Network-controlled values in size calculations",
          cwes: ["CWE-190"],
        },
      ],
      safePatterns: [
        {
          api: "calloc(n, size)",
          why: "calloc checks for overflow internally on most implementations",
        },
        {
          api: "Explicit overflow check before arithmetic",
          why: "if (a > SIZE_MAX / b) return error",
        },
      ],
      investigationHints: {
        grepPatterns: [
          "malloc\\(.*\\*",
          "realloc\\(",
          "ntohs\\(",
          "ntohl\\(",
          "\\(int\\)",
          "\\(unsigned\\)",
        ],
        fileHints: [
          "Memory allocation wrappers",
          "Protocol deserialization code",
          "Image/media parsing (width * height * bpp patterns)",
        ],
        instructions: [
          "Look for multiplication in malloc/realloc arguments where both operands come from untrusted input",
          "Check for narrowing casts (uint32_t -> uint16_t, size_t -> int) before size comparisons",
          "Trace ntohs/ntohl results through arithmetic to allocation or copy calls",
        ],
      },
      fewShots: [
        {
          scenario: "Image dimension multiplication overflow",
          vulnerableCode:
            "uint32_t width = read_u32(input);\nuint32_t height = read_u32(input);\nchar *pixels = malloc(width * height * 4);\nmemcpy(pixels, data, width * height * 4);",
          explanation:
            "width * height * 4 can overflow uint32_t, wrapping to a small value. malloc allocates too little, memcpy overflows the heap buffer.",
        },
      ],
      antiHallucinationExtra: [
        "calloc(n, size) typically checks for overflow internally — verify before flagging",
        "Overflow in dead code paths or with hardcoded safe values is NOT exploitable",
      ],
    },
    "use-after-free": {
      sinks: [
        {
          api: "free(ptr); ... use(ptr)",
          risk: "Accessing freed memory — attacker may control reallocated content",
          cwes: ["CWE-416"],
        },
        {
          api: "realloc may return different ptr",
          risk: "Old pointer becomes dangling if realloc moves the allocation",
          cwes: ["CWE-416"],
        },
        {
          api: "Double free",
          risk: "Freeing same pointer twice corrupts allocator metadata",
          cwes: ["CWE-415"],
        },
      ],
      safePatterns: [
        {
          api: "ptr = NULL after free",
          why: "Prevents use-after-free if subsequent code checks for NULL",
        },
        {
          api: "Reference counting with atomic ops",
          why: "Prevents premature free in concurrent code",
        },
      ],
      investigationHints: {
        grepPatterns: ["free\\(", "realloc\\(", "->.*=.*NULL"],
        fileHints: [
          "Object lifecycle management code",
          "Error handling paths (goto cleanup patterns)",
          "Callback/event handler registration",
        ],
        instructions: [
          "Look for error paths where free is called but the function continues to use the pointer",
          "Check callback registrations — is the callback's context freed before the callback fires?",
          "In goto-cleanup patterns, verify that the cleanup sequence matches the allocation order",
          "Check for race conditions between free and use in multi-threaded code",
        ],
      },
      fewShots: [
        {
          scenario: "Error path use-after-free",
          vulnerableCode:
            'buf = malloc(size);\nif (parse(buf, input) < 0) {\n    free(buf);\n    log_error("parse failed for %s", buf->name);\n    return -1;\n}',
          explanation:
            "On parse failure, buf is freed but then dereferenced in the log_error call to access buf->name.",
        },
      ],
      antiHallucinationExtra: [
        "A free followed by return (with no intervening use) is NOT a use-after-free",
        "Static analysis may flag theoretical UAF that requires specific thread interleaving — assess reachability",
      ],
    },
    "format-string": {
      sinks: [
        {
          api: "printf(user_str)",
          risk: "User-controlled format string enables read/write of stack memory",
          cwes: ["CWE-134"],
        },
        {
          api: "fprintf(f, user_str)",
          risk: "Same as printf — format string from untrusted source",
          cwes: ["CWE-134"],
        },
        { api: "syslog(priority, user_str)", risk: "Format string via syslog", cwes: ["CWE-134"] },
        {
          api: "snprintf(buf, size, user_str)",
          risk: "Bounded output but format string still attacker-controlled",
          cwes: ["CWE-134"],
        },
      ],
      safePatterns: [
        { api: 'printf("%s", user_str)', why: "User string passed as argument, not format — safe" },
        {
          api: "Hardcoded format string with user args",
          why: "Format is constant, only arguments vary",
        },
      ],
      investigationHints: {
        grepPatterns: ["printf\\(", "fprintf\\(", "syslog\\(", "snprintf\\(", "sprintf\\("],
        fileHints: ["Logging functions", "Error message handlers", "Debug output code"],
        instructions: [
          "Check if the first argument to printf-family functions is a variable (not a string literal)",
          "Trace the variable back — does it come from user input, network data, or file content?",
          "Custom logging wrappers may forward to printf internally — check their implementation",
        ],
      },
      fewShots: [
        {
          scenario: "SNMP error handler format string",
          vulnerableCode:
            "char *community = snmp_get_community(pdu);\nsnprintf(errbuf, sizeof(errbuf), community);",
          explanation:
            "community string comes from network SNMP packet and is used as format string in snprintf. Attacker sends %x%x%x%n to read/write stack.",
        },
      ],
      antiHallucinationExtra: [
        'printf("%s", var) is SAFE — the format string is the literal "%s", not the variable',
        "Do NOT flag printf with hardcoded format strings and user data as arguments",
      ],
    },
    "type-confusion": {
      sinks: [
        {
          api: "Tagged union access without type check",
          risk: "Accessing wrong union member reads garbage or attacker-controlled data",
          cwes: ["CWE-843"],
        },
        {
          api: "void* cast without validation",
          risk: "Casting to wrong concrete type",
          cwes: ["CWE-843"],
        },
        {
          api: "Variant/discriminated type access",
          risk: "Missing discriminator check before accessing type-specific fields",
          cwes: ["CWE-843"],
        },
      ],
      safePatterns: [
        { api: "switch(tag) with all cases", why: "Exhaustive tag check before union access" },
        { api: "assert(obj->type == EXPECTED) before cast", why: "Runtime type validation" },
      ],
      investigationHints: {
        grepPatterns: [
          "union\\s+\\{",
          "\\.type\\s*==",
          "->type\\s*==",
          "\\(struct\\s+\\w+\\s*\\*\\)",
        ],
        fileHints: [
          "ASN.1 / TLV parsing code",
          "Protocol message handlers with type-dispatched processing",
          "Variant/tagged-union type definitions in headers",
        ],
        instructions: [
          "Find union types and their discriminator fields, then check every access site for discriminator validation",
          "Look for void* parameters cast to concrete types — is the type guaranteed by the caller contract?",
          "In TLV/ASN.1 parsers, check that the type tag is validated before accessing type-specific content",
        ],
      },
      fewShots: [
        {
          scenario: "ASN.1 value access without tag check",
          vulnerableCode:
            "ASN1_VALUE *val = asn1_parse(input);\nint len = val->value.str_val->length;",
          explanation:
            "val could be INTEGER, BOOLEAN, or STRING type. Accessing str_val without checking val->type reads memory from the wrong union member if val is not a string.",
        },
      ],
      antiHallucinationExtra: [
        "If a switch/case exhaustively handles all type tags before union access, it is safe",
        "Internal functions where the caller always passes the correct type (verified by code inspection) are lower risk",
      ],
    },
    "command-injection": {
      sinks: [
        {
          api: "system(cmd)",
          risk: "Passes cmd to /bin/sh -c for full shell interpretation",
          shellInvoking: true,
          cwes: ["CWE-78"],
        },
        {
          api: "popen(cmd, mode)",
          risk: "Shell interpretation of cmd string",
          shellInvoking: true,
          cwes: ["CWE-78"],
        },
        {
          api: "execlp/execvp with shell wrapper",
          risk: "If first arg is a shell and command is user-controlled",
          shellInvoking: true,
          cwes: ["CWE-78"],
        },
      ],
      safePatterns: [
        {
          api: "execve with argument array",
          why: "No shell interpretation when using direct exec with argv",
        },
        { api: "Hardcoded command string", why: "No attacker-controlled input in the command" },
      ],
      investigationHints: {
        grepPatterns: ["system\\(", "popen\\(", "execlp\\(", "execvp\\("],
        fileHints: ["Build scripts and helper utilities", "CGI/web handler code"],
        instructions: [
          "Check if user-controlled data (environment variables, HTTP parameters, file content) reaches system/popen",
          "Look for string concatenation or sprintf building command strings with untrusted data",
        ],
      },
      fewShots: [
        {
          scenario: "CGI handler building shell command",
          vulnerableCode:
            'char cmd[512];\nsnprintf(cmd, sizeof(cmd), "convert %s output.png", filename);\nsystem(cmd);',
          explanation:
            "filename comes from user upload/request. Attacker sends 'img.png; rm -rf /' — shell interprets the semicolon as command separator.",
        },
      ],
      antiHallucinationExtra: [
        "execve/execv with a fixed argv array and no shell is NOT vulnerable to metacharacter injection",
        "system() with a fully hardcoded string and no user input is NOT a vulnerability",
      ],
    },
  },
};
