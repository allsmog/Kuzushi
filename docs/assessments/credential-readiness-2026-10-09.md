# Credential readiness, October 9, 2026

The readiness audit found expired-but-refreshable OAuth collapsed into OAuth
ready in Setup and Health. The shared probe already distinguished those states.
Model hints also claimed readiness or connection from local credential presence,
and the credential chooser called a stored connection ready before provider
acceptance. These labels overstated what the local checks establish.

## Changes

Setup preserves API-key presence, stored OAuth, refresh-required OAuth,
environment OAuth, session-key presence, missing credentials and OAuth requiring
repair. Refresh-required credentials have an attention marker instead of a
success check. An unrefreshable or malformed stored credential blocks
model-backed Setup work with a repair explanation. Deterministic selections
still need no credential. No model, provider, refresh policy or budget authority
changes.

The presence classifier preserves the adapter's credential precedence: an
explicit session key, then the provider's API key, then its OAuth state. API keys
are not treated as OAuth credentials for the selected subscription namespace.
Unsupported provider presence no longer becomes an invented API-key source.
The shared probe remains responsible for OAuth shape and expiry.

Auth and Model hints say stored, present or refresh required. Health shows
unverified presence as a warning and invalid OAuth as failure. A present value
never establishes provider acceptance. The credential chooser describes the
same expired state and never presents a stored token as a verified connection.
Values remain hidden. Narrow Setup no longer drops the credential explanation
after two lines. This change does not replace runtime preflight, authenticate a
token or perform refresh.

## Evidence

Evidence is under `/tmp/kuzushi-credential-readiness-20261009`. Thirteen Setup
tests include real owned credential files, expiry, unrefreshable repair, shared
state projection, source precedence, model retention and deterministic-work
independence. Auth tests preserve value redaction and remove connection claims.
Health tests prove warning versus failure without exposing credential values.
Credential-picker regressions retain draft ownership, recovery and explicit
model switching. Setup rendering regressions and a focused 40-column test keep
the complete explanation and attention marker. The environment-token regression
continues to pass.

J138 uses synthetic credential metadata in an isolated home over owned
comment-only source. It inspects Setup, Health and the credential chooser without
confirming sign-in or starting Map. Expired-refreshable, expired-unrefreshable
and locally stored states remain distinct. Six sizes and no-color restart are
captured. The fixture authenticates unchanged source and credential bytes,
hidden values and absence of provider reservations, work attempts, findings and
scan queues. No real credential is read or modified by this isolated journey.
The final capture receipt and scoped review remain separate from operator
approval; raw REVIEW_REQUIRED is preserved.

Final J138 is
`/tmp/kuzushi-credential-readiness-20261009/tui/20261009-032351/J138`:
twenty-five machine passes, zero failures, five human questions and twenty-four
authenticated live capture pairs. Six no-color frames contain no color SGR
sequences. Native SHA-256:
`f831be509b749391ae15c19656483bc034dc30ff639041dc5e942487c49cdc08`.
Four scoped screen judgments pass. One stays partial: the full credential
explanation is visible at 40x12, but the generic Setup footer clips Enter
guidance. Paging leaves the same frame because that explanation already fits.
The scoped review does not substitute for operator acceptance.

Retained failures include a copy assertion for an old stored-connection phrase,
a Setup assertion that missed its correct REPAIR label, a whole-Health assertion
that confused model/runtime guidance with credential guidance, and a quit check
that omitted confirmation of unsaved test selections. These fixture corrections
are separate from the production attention and disclosure repairs. The driver
stays unchanged. All ten quick gates and the native build pass on dirty main;
the verifier conservatively marks dirty snapshots as drifted during the run.

## Remaining work

The latest real-model attempt still requires OAuth recovery and a specifically
approved allowance before another request. Synthetic metadata validates this
state presentation, not successful refresh, provider acceptance or model
usefulness. Wider provider combinations, preparation-wide cancellation,
target-specific engine prerequisites, the complete per-tool outcome audit,
large monorepo interaction and full TUI parity remain open. No module maturity
or full delivery milestone is promoted by these checks.

## Compact hint follow-up

The later report checkpoint repairs the clipped Setup prompt with compact picker
guidance that keeps movement, Enter selection and command entry visible. J138
at `/tmp/kuzushi-confirmed-sarif-20261009/credential-tui/20261009-041322/J138`
records twenty-seven machine passes, no failures and twenty-four live captures.
The forty-column frame shows the full credential explanation and all three
controls. Five scoped judgments pass, including six sizes and no-color restart.
The owned fixture again records unchanged source and credentials, hidden values
and no authentication, refresh, provider or scanner work. Exact binary and
capture receipts remain alongside the separate scoped review. The broader
limits above and raw REVIEW_REQUIRED remain unchanged.
