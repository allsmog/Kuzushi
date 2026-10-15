# Review input during finite native work

The complete monorepo journey now measures the Review composer while the
approved native scan dispatcher remains live. Earlier timing covered Logs and
inventory waits; it did not establish the same behavior in Review as findings
arrived from native jobs.

The new fixture reuses the existing owned-pane, dispatcher identity and echo
observers. Before and after every sample it checks the same PID, campaign,
target, loaded executable and unfinished fixed workload. It never starts or
restarts work to rescue an observation. Timings run from immediately before
`send-keys` until after the pane capture returns, including tmux IPC/capture
overhead. Four samples at each of six sizes meet the 300 ms fixture bound.

| Terminal | Samples | Observed echo range |
| --- | ---: | --- |
| 40x12 | 4 | 20.47 to 21.47 ms |
| 60x20 | 4 | 20.04 to 22.51 ms |
| 80x24 | 4 | 21.61 to 33.53 ms |
| 96x89 | 4 | 34.50 to 36.73 ms |
| 120x36 | 4 | 23.37 to 33.57 ms |
| 160x48 | 4 | 32.79 to 34.62 ms |

The overall median is 28.05 ms and the largest sample is 36.74 ms when rounded
up to two decimals. These are local send-to-observed-echo samples under one
native workload, not stable tail percentiles, a worst-case guarantee, physical
keyboard/display timing or reference-product parity.

The existing warmed canonical Review renderer tests also pass serially with
400 labeled synthetic findings. Navigation input-to-paint p95 is 4.52 ms;
single-key Prompt input-to-paint p95 is 5.85 ms and a 40-character burst is
8.38 ms, rounded up to two decimals. Their budgets are 50, 25 and 50 ms.
The third warmed test records 0.48 ms of thread CPU over 302.66 ms of idle
polling. These TestBackend/terminal-loop results are separate from native
tmux observations and do not certify physical display latency.

## Complete journey and limits

J206 records 70 machine passes, zero failures, 56 live text/ANSI capture pairs
and five pending human judgments. Review retains `retained-review-draft` and
its reading origin after all nine native jobs complete. The actual workers
produce nine observations from three accepted primary scopes, with shared
context kept separate. Three scripted human deferrals, Report, a subsequent
unaccepted scope edit and no-color restart retain the original scope study
and shared accounting. There is no injected queue completion, model request,
provider reservation or target source execution.

This increment changes the fixture, journey and acceptance documentation only.
Production Rust source is unchanged from `4e4e97cfd4`; its locked workspace
build and frozen 13-executable bundle are reused. Native SHA-256:
`fd253fb4fe3198022507987f0d85dfa1ff09190d23a57cdd283446d8c674e6f7`.
The three current warmed performance tests pass. The broader Rust suite,
CI/platform matrix and every active input surface remain unqualified.

Evidence root: `/tmp/kuzushi-tui-integration-20261012`.
Native run: `active-review-shared-tui/20261014-232102/J206`.
Samples: `active-review-timing.json` in that run.
Warmed tests: `active-review-render-performance.log`.
Current capture hashes/provenance and assistant content judgments are retained
separately. Assistant review does not approve the five human judgments.
The earlier passing run and its original observer/journey sources remain under
`active-review-tui/20261014-230509/J206`. The final wrapper delegates timing to
the existing shared observer instead of maintaining a duplicate sample loop.

The [acceptance ledger](../quality/bounded-investigation-acceptance.md) now
distinguishes scoped evidence from concrete missing functionality. Review still
lacks a goal-relevance assessment/view tied to the accepted brief, separate
from finding verdicts. That is a product gap, while larger-model usefulness and
full UX/reference acceptance remain qualification work. No broad milestone is
closed and the exhausted live allowance is unchanged.
