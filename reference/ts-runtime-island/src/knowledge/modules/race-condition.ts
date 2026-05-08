import type { KnowledgeModule } from "../types.js";

export const raceConditionModule: KnowledgeModule = {
  id: "race-condition",
  cwes: ["CWE-362", "CWE-367"],
  languages: [],
  frameworks: [],
  dangerousPatterns: [
    {
      pattern: "Check-then-act without locking",
      why: "TOCTOU race between validation and operation",
      severity: "ERROR",
    },
    {
      pattern: "Balance check then debit without transaction",
      why: "Concurrent requests can overdraw accounts",
      severity: "ERROR",
    },
    {
      pattern: "File existence check then open",
      why: "File state can change between check and use",
      severity: "WARNING",
    },
    {
      pattern: "Read-modify-write without atomic operation",
      why: "Lost updates under concurrent access",
      severity: "WARNING",
    },
    {
      pattern: "Shared mutable state without synchronization",
      why: "Data corruption under concurrent access",
      severity: "WARNING",
    },
  ],
  safePatterns: [
    {
      pattern: "Database transactions with serializable isolation",
      why: "Prevents concurrent conflicting operations",
    },
    { pattern: "Atomic compare-and-swap operations", why: "Hardware-level atomicity guarantees" },
    { pattern: "Mutex/lock around critical sections", why: "Serializes access to shared state" },
    {
      pattern: "Optimistic locking with version columns",
      why: "Detects concurrent modifications at commit time",
    },
  ],
  bypassTechniques: [
    "Send concurrent requests to trigger TOCTOU window",
    "High-frequency polling to hit narrow race windows",
    "Slow down one operation to widen the race window",
    "Exploit async/callback ordering differences",
    "Database isolation level downgrade exploitation",
  ],
  detectionKeywords: [
    "lock",
    "mutex",
    "synchronized",
    "atomic",
    "transaction",
    "balance",
    "inventory",
    "stock",
    "quota",
    "limit",
    "check",
    "verify",
    "validate",
    "then",
    "update",
  ],
  fixExamples: [
    {
      language: "SQL",
      before:
        "SELECT balance FROM accounts WHERE id = ?; UPDATE accounts SET balance = balance - ? WHERE id = ?;",
      after: "UPDATE accounts SET balance = balance - ? WHERE id = ? AND balance >= ?;",
      explanation: "Combine check and update into a single atomic SQL statement",
    },
  ],
  tags: ["race-condition", "concurrency", "toctou", "timing"],
};
