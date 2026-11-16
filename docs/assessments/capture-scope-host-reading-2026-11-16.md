# The suppression sweep read the wrong host out of a captured request (2026-11-16)

## The defect

`suppressions/domain/evaluate.rs` evaluates the `scope_status` predicate, which
exists for one rule: `compile_scope_rule` turns a non-empty
`<workspace>/.kuzushi/scope.toml` into the synthetic rule
`sup-scope-out-of-scope`, whose predicate is `scope_status == OutOfScope` and
whose reason is `out-of-scope`. To decide that, `finding_scope_verdict` needed
the host a finding names, and `finding_host` derived it by scanning the raw
request blob:

```rust
fn request_blob_host(blob: &str) -> Option<String> {
    for line in blob.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Host:").or_else(|| trimmed.strip_prefix("host:"))
        { /* … */ }
        if let Some(url) = request_line_url(trimmed) {
            return Some(url);
        }
    }
    None
}

fn request_line_url(line: &str) -> Option<String> {
    let candidate = line.split_whitespace().find(|token| token.contains("://"))?;
    Some(candidate.to_string())
}
```

Every line of the whole message was a candidate, and on each line *any*
whitespace-delimited token holding `://` was accepted as the host — before the
`Host` field was ever reached, because the request line is line one. So the
first URL anywhere in the message decided the verdict:

- **In the request target.** `GET /redirect?next=https://partner.out-of-scope.test/ HTTP/1.1`
  reads as the host `partner.out-of-scope.test`. A URL in a query string is the
  ordinary shape of the redirect, callback, and SSRF testing a bounty engagement
  is made of.
- **In a header before `Host`.** Field order is not fixed, so a `Referer`,
  `Origin`, or `User-Agent` URL wins over the `Host` field that follows it.
- **In the body.** There is no head/body boundary in the loop, so a webhook or
  OAuth payload naming `https://out-of-scope.test/cb` decides the host of a
  request that was never sent there.

Two narrower readings sat beside it: `Host:`/`host:` are two spellings of a
field name HTTP defines as case-insensitive (RFC 9110 §5.1), and an HTTP/2
`:authority` pseudo-header names the host but is not a `Host` field.

## What that cost

The verdict is not a label; it gates.

1. `run_suppression_sweep` runs on scan start, on TUI target load, and —
   through `reconcile_suppressions_before_gate` — immediately before the
   `--fail-on` gate. It evaluates, then `reconcile_suppression_events` appends
   `SuppressionAdded` for every newly-active match.
2. That event projects the finding's `current_status` to `suppressed`.
3. `scan_gate.rs::count_blocking_findings_for_run_ids` counts a finding only
   `if !finding.suppressed`.

So a finding on an in-scope host whose request carried an out-of-scope URL was
annotated `out-of-scope` — "Host is out of program scope (scope.toml)." — and
**dropped out of the CI gate**. `kuzushi scan --fail-on high` exits 0 over it.

It also put the two scope decisions about one finding in disagreement.
`import_har` and `import_burp_xml` gate per entry on the URL the capture
recorded (`request.url`, `<url>`) and *admitted* the finding as in scope; the
sweep then re-derived a different host from the blob and suppressed what the
import gate had just let through.

Verified against the pre-fix code: both regression tests fail, the in-scope
capture reporting
`Active(SuppressionMatch { rule_id: "sup-scope", origin: ScopeToml, … })`.

## Why this ranked first

Ten problems were ranked this run (the PR body lists them). This one won on
four counts: the consequence is a **real finding silently removed from the
CI gate** and recorded as out of program scope, which is the strongest form of
the dishonest-label failure this repository keeps closing; the trigger is
ordinary traffic, not a crafted message — a `?next=` parameter, a browser
`Referer`, a callback URL in a body; it is completely silent, with the
suppression reason the only trace and nothing in it naming the host it read;
and the fix is deterministic, model-free, and confined to one private helper
with no schema or option change.

## The change

`finding_host` now reads the host from the two places that state it.

- **The URL the capture recorded.** Both importers write their gated `url` into
  the evidence's `file_path`, and `is_target_source_citation` excludes
  `http-request` from filesystem citation handling, so that field is a URL by
  contract rather than a target-relative path. `recorded_target_url` takes it
  when it carries a scheme, which keeps a non-URL `file_path` from any other
  producer out of the host reading — `verdict` would read `src/app.rs` as the
  host `src` and match no rule. Reading it is what keeps the sweep's verdict
  the one the import gate already reached about the same finding.
- **The request message head**, for evidence that recorded no URL.
  `request_head_host` reads the request line's absolute-form target first and
  the `Host` field second (RFC 9112 §3.2, §3.3), and nothing else:
  `absolute_form_target` takes the line's *second field* and requires it to
  begin with an RFC 3986 scheme, so a `://` elsewhere on the line belongs to a
  value the target carries; the header search stops at the first empty line, so
  the body is never read; and `host_field_value` compares the whole field name
  case-insensitively, which admits `HOST:` and rejects both a folded
  continuation line and `:authority`.

## What is not claimed

- **Findings mis-suppressed by the old reading are reopened, not rewritten.**
  The next sweep evaluates them as `SuppressionState::None` with a
  rule-originated suppression on record, which is exactly the
  `SuppressionRemoved` path `reconcile_suppression_events` already owns. The
  earlier `SuppressionAdded` event stays in the log, because it happened.
- **A request that names no host still yields no verdict.** An HTTP/2 capture
  whose only authority is `:authority`, or a `CONNECT` in authority form, gives
  `None`, so the `scope_status` predicate does not match and the finding stays
  visible. That is the pre-existing behavior for a host the gate cannot name,
  and it is the safe direction.
- **Nothing changes for a capture whose message agrees with its URL**, which is
  every capture whose request target is origin-form with a `Host` field and no
  other URL before it. `scope_status_only_matches_host_bearing_findings` passes
  unchanged, including its blob-only evidence.
- **The import-time scope gates are untouched.** They already read the recorded
  URL; this change makes the sweep agree with them rather than replacing them.
- **No schema, artifact, option, or CLI surface changes.** The three new
  helpers are private to `evaluate.rs`.
