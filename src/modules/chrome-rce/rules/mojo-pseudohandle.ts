/**
 * Rule 1 — chrome-rce-mojo-broker-pseudohandle-reject
 *
 * Anchored to CVE-2025-2783 (Operation ForumTroll, March 2025, ITW).
 *
 * The bug: a Mojo broker on Windows called ::DuplicateHandle with a HANDLE
 * value supplied by an attacker-controlled renderer process, without first
 * rejecting Win32 pseudo-handles. The pseudo-handle set is a closed enum
 * (-1..-6: current process, current thread, process token, thread token,
 * impersonation tokens). When the source HANDLE is a pseudo-handle,
 * DuplicateHandle does NOT look up a kernel object; it duplicates the
 * broker's own pseudo-resource into the renderer. The renderer sent
 * (HANDLE)-2 (current thread) and got a real handle to the broker thread
 * back, then used SuspendThread/SetThreadContext to take over the broker.
 *
 * The detection: scan IPC/broker-shaped paths for DuplicateHandle calls
 * whose source-handle argument is not preceded by a pseudo-handle reject.
 * The `pattern-not-inside` clauses cover the common forms of the reject
 * (`IsPseudoHandle(h)`, `h == INVALID_HANDLE_VALUE`, `(intptr_t)h > 0`).
 */

export const RULE_ID = "chrome-rce-mojo-broker-pseudohandle-reject";

export const MOJO_PSEUDOHANDLE_YAML = String.raw`rules:
  - id: chrome-rce-mojo-broker-pseudohandle-reject
    message: |
      ::DuplicateHandle is called on a HANDLE that appears to come from an
      IPC peer, without a preceding reject of Win32 pseudo-handles
      (INVALID_HANDLE_VALUE / current-process / current-thread / token
      pseudo-handles, all in the closed enum -1..-6). On Windows,
      DuplicateHandle of a pseudo-handle duplicates the BROKER's own
      resource into the peer process — that is sandbox escape. Anchored to
      CVE-2025-2783 (Operation ForumTroll, March 2025, ITW). Add an
      IsPseudoHandle()-style reject before the DuplicateHandle call, or
      reject any HANDLE whose intptr_t representation is <= 0.
    severity: ERROR
    languages: [cpp]
    metadata:
      cwe: ["CWE-862: Missing Authorization"]
      confidence: HIGH
      likelihood: HIGH
      impact: HIGH
      subcategory: ["chrome-rce", "mojo-broker", "ipc-validation"]
      references:
        - "https://nvd.nist.gov/vuln/detail/CVE-2025-2783"
        - "https://securelist.com/operation-forumtroll/115989/"
    patterns:
      - pattern-either:
          - pattern: ::DuplicateHandle(...)
          - pattern: DuplicateHandle(...)
          - pattern: base::win::DuplicateHandle(...)
      - pattern-not-inside: |
          if (IsPseudoHandle(...)) {
            ...
          }
          ...
      - pattern-not-inside: |
          if (!IsPseudoHandle(...)) {
            ...
          }
          ...
      - pattern-not-inside: |
          if ($H == INVALID_HANDLE_VALUE) {
            ...
          }
          ...
      - pattern-not-inside: |
          if ($H == nullptr) {
            ...
          }
          ...
      - pattern-not-inside: |
          if ((intptr_t)$H > 0) { ... }
          ...
      - pattern-not-inside: |
          if (reinterpret_cast<intptr_t>($H) > 0) { ... }
          ...
      - pattern-not-inside: |
          if (!IsValidHandleValue($H)) { ... }
          ...
    paths:
      include:
        - "**/ipc/**"
        - "**/mojo/**"
        - "**/broker*/**"
        - "**/services/**"
        - "**/sandbox/**"
`;
