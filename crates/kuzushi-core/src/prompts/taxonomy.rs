//! Versioned false-positive taxonomy shared by triage, verification, deep
//! auditor, IRIS-Next, and the finding-producing scanners. This merges the
//! previously duplicated false-positive knowledge into one source of truth.

/// Common false-dismissal traps and true false positives, each requiring cited
/// rationale before a finding is cleared.
pub const FALSE_POSITIVE_TAXONOMY: &str = "Reject-by-design only with explicit cited rationale.

Common false-DISMISSAL traps. Do not clear a finding on these alone; re-investigate:
- \"WAF/framework will catch it\": WAFs are bypassable; template engines have raw modes; \
  DOM-XSS is client-side; framework defaults vary by context.
- \"We use parameterized queries\": check ORM misuse, dynamic SQL in stored procedures, \
  string interpolation before binding, query fragments, and second-order injection.
- \"Extension check makes upload safe\": check null bytes, double extensions, parser \
  discrepancies, content sniffing, MIME confusion, archive extraction, and storage paths.
- \"Frontend/client-side validation\": client-side validation is UX, not a security guard.
- \"Internal, so auth does not matter\": SSRF, lateral movement, and compromised internal \
  users make internal paths relevant.
- \"Low severity, not worth flagging\": low-severity issues can chain into critical paths.

Common true false positives. Safe to reject only with cited evidence:
- Documented passthrough: a parameter named sql/query/cmd/script/expression passed as the \
  entire input to SPI_execute, eval, exec, Function, Runtime.exec, database/sql, or similar \
  APIs is not injection by itself. Real injection requires attacker data concatenated, \
  formatted, or interpolated into a larger command/query fragment.
- Role-gated privileged primitives: dlopen, system, exec, file I/O, configuration writes, \
  or administrative endpoints reachable only after a cited superuser/admin/role-membership \
  check can be intended privileged functionality.
- Superuser-only configuration: archive_command, restore_command, shell command settings, \
  dynamic extension loading, and equivalent operator-only settings are not findings without \
  an unprivileged control path.
- Offline/argv-only tooling: build tools, migrations, test harnesses, local scripts, and \
  CI-only paths are not runtime attack surface unless evidence ties them to attacker input.
- Constant sinks: string-literal sink arguments proven constant by syntax evidence are not \
  attacker controlled.
- Centralized validators: upstream dispatchers, routers, schema validators, auth middleware, \
  and protocol parsers can enforce invariants missing in the local frame. Check these before \
  voting true-positive on a missing-local-check finding.
- Sanitizer-shaped names are hypotheses, not proof: validate_*, sanitize_*, escape_*, \
  is_safe*, get_safe*, canonicalize_*, check_* must have their bodies inspected for skipped \
  checks, prefix-only allowlists, validation before canonicalization, pre-concatenation-only \
  validation, or trusted branches that still process caller-controlled input.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taxonomy_covers_dismissal_traps_and_true_false_positives() {
        assert!(FALSE_POSITIVE_TAXONOMY.contains("false-DISMISSAL traps"));
        assert!(FALSE_POSITIVE_TAXONOMY.contains("Sanitizer-shaped names are hypotheses"));
        assert!(FALSE_POSITIVE_TAXONOMY.contains("Centralized validators"));
    }
}
