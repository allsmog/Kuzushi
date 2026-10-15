# Existing advisory context yields an unaccepted bounded draft

`ndiff:extract-fix-pattern` previously forced high reasoning and bypassed
investigation accounting because ExternalAction did not support an allowance.
Its declared patchPath was not consumed. Truncation at a fixed 18,000-byte offset
could panic inside a UTF-8 character. Any JSON object was accepted as a pattern,
and the result did not disclose unaccepted authority or exact source omissions.

Extraction now opts into Learning accounting. Shared dispatch requires approved
capacity before a model request, while keeping external-action authorization.
Tagged external actions cannot borrow an inherited Review category. Untagged
external actions keep their existing contract pending their own audits. The
whole `ndiff` module is Labs, with exact dispatch retained and no Core module
entry containing only experimental actions. Extraction remains auxiliary Map;
discovery remains auxiliary Scan. Neither owns a phase checkpoint.

The request inherits selected reasoning and has no source tools or MCPs. It
requests 4,096 output tokens and one model turn by default. Declared bounds allow
256 to 32,768 requested tokens and one to four turns; a structured repair uses
the same model, reasoning and limits under another reservation. Requested token
limits do not establish provider enforcement or a strict dollar ceiling.

Supplied metadata is counted before copying or parsing its record. Existing
diff text is checked before cloning. The accepted source limit defaults to
256 KiB, with an 8 MiB maximum. Combined supplied advisory and diff fixtures
default to a 64 KiB encoded limit, with an 8 MiB maximum. The resolved body is
checked after retrieval; these limits do not replace live transport bounds.
Source-only file consumption uses an exact bounded read beneath the selected
target and rejects symlinked path components. Inline patchText takes precedence
when both sources are supplied. id, offline, fixtures, patchFixtures and the
curl binary are now declared options for their existing compatibility paths.

The source excerpt defaults to 18,000 bytes and accepts 256 to 128 KiB. Its
boundary is UTF-8 safe. The initial metadata/excerpt prompt must fit the
declared context bound before a request, default 64 KiB, range 1,024 to 512 KiB.
The versioned source receipt records full-content digest, supplied/resolved byte
count, included and omitted bytes, source kind and sourceVerified=false. This
records the supplied content identity. Source and advisory claims remain unverified.

Required fixShape and vulnerableShape output must be nonblank text of at most
4,096 bytes each. Historical snake-case shapes remain readable. The draft retains
legacy advisory, pattern and patchUrl fields, with additive draft=true,
accepted=false and contextActivated=false. Excerpted input is partial and leads
with its unaccepted status and source limitation. Full supplied input can complete
the draft task without accepting its claims or advancing Map. A separate explicit
search consumes the pattern; no worker or DAG creates that search automatically.

Cancellation is checked before source resolution, before the model request and
before draft publication. Cancellation during retrieval, output-body and
repair-guidance bounds, complete-file retention, retrieval authenticity, useful
patterns and final human UX review remain open.
Two unused permissive JSON helpers are removed after their last consumers adopt
required shape/observation checks; no module or public tool name is removed.

| Audit dimension | Evidence and limits |
| --- | --- |
| Purpose | A draft context pattern describing supplied existing changes. It generates no patch, reproducer or finding verdict. Useful transfer remains unqualified. |
| Phase | Labs auxiliary Map with Learning accounting; authorization is retained and phase ownership is disabled. |
| Inputs | Explicit target, selected model, source text/file/reference, declared limits and approved allowance. Metadata, source and prompt bounds reject before a request. |
| Execution | Prepared dispatch exercises source consumption, request construction, repair and explicit artifact consumption by a separately requested search. |
| Outputs | Unaccepted draft plus full supplied-content identity and exact source omissions. No context activation, accepted lesson or automatic discovery. |
| Failure | Invalid settings, missing allowance, missing required output, symlink/outside files, source/context limits, cancellation and protected Review are covered. Live retrieval remains unqualified. |
| Resources | Learning reservations share the investigation with Discovery and preserve Review. No source tools; initial and repair requests keep selected limits. Dollar consumption remains uncertain. |
| Scope | Bounded supplied diff context only. It does not establish repository coverage or enforce an accepted discovery scope. |
| Interfaces | Canonical preparation owns declared options and aliases. Exact CLI/TUI evidence is recorded separately below. |
| Product value | Removes hidden reasoning, an accounting bypass, a broken file option and unsafe truncation. Pattern usefulness still needs real evidence. |

Verification is recorded under
`/tmp/kuzushi-tui-integration-20261012/advisory-pattern-audit`.
Eighty-one distinct focused Rust checks and the locked workspace build pass:
ten extraction contracts, 42 capability checks, 13 allowance checks, nine
advisory-search contracts, the unchanged 184-tool policy inventory and six shell
phase-ownership checks. The full Rust suite was not run.

Eleven native CLI cases include successful file consumption with normal and
plain/no-color output. Each success uses one fully intercepted request and
retains an unaccepted complete-input draft. Missing model/allowance/file,
unsupported scope and invalid settings fail before a request. A supplied-source
limit produces a durable failed result with exit three; the initial CLI assertion
incorrectly expected exit two. The corrected evidence distinguishes invocation
failure from a failed tool result instead of changing product behavior.

J246 records 14 machine passes, zero failures and 14 authenticated capture pairs
across six sizes and no-color restart. It explicitly confirms extraction, retains
255 included bytes at a UTF-8 boundary and then separately requests the search.
Two fully intercepted GPT-5.5 medium responses commit two calls from one
investigation, preserving one protected Review call. The draft request has zero
tools; the search returns no tool calls. Exact human decision, source, active
context and draft digest remain unchanged. Accepted lessons remain empty and
neither action creates a phase continuation. Native OAuth omits the requested
output-token cap, so provider token enforcement is unqualified. Cost remains
unavailable. Four human questions remain pending and operatorApproved is false;
raw status is REVIEW_REQUIRED. Product SHA-256:
`6b16a799909640b09077f8435943101de8a885d91d8abc0457be6a6061a799da`.
Captures:
`/tmp/kuzushi-tui-integration-20261012/advisory-pattern-tui/20261014-014550/J246`.

Sequential J121 on the same immutable build records 109 machine passes, zero
failures and 87 authenticated capture pairs. Its four responses are fully
intercepted; finite plans, protected Review, partial reports, source reassessment
and restart retain their receipts. Fifteen human questions remain pending.
Captures:
`/tmp/kuzushi-tui-integration-20261012/advisory-pattern-complete-tui/20261014-014915/J121`.

The ten checked-in quick gates pass, with 391 Node checks and the CRAP-risk
proxy over 599 changed code files. Retained initial failures include incorrect
Rust hash/policy assumptions and an overlong prompt builder; the implementation
now uses the shared content digest and a separate advisory formatter. No failed
attempt is credited as a pass. The visible catalog retains 113 actions: 85 Core,
23 Labs and five Compatibility. Eight in-scope tools remain unassigned.

The live allowance remains exhausted at six of six. Owned responses are fully
intercepted with dummy OAuth; no live request or target execution is authorized
in this increment. No exploit, reproducer or vulnerability patching is performed.
No broad milestone closes.
