# Prepared input survives failed and interrupted requests

Deep discovery now retains its prepared input before entering the runtime.
The authenticated `prepared-model-input.json` version 1 envelope records the
run identity, tool and input data, including the serialized `AgentQueryRequest`.
The original prompt string, system instructions, model and request options are
preserved. A 1 MiB encoded limit bounds retention. Storage failure prevents the
request. A terminal lock prevents concurrent replacement, and a retained record
cannot be replaced even if its file is later deleted.

Failed and canceled receipts reuse the retained input. Process recovery adds it
to an interrupted result and retains its artifact listing. Reading authenticates
the saved bytes; missing or changed bytes produce an explicit Inputs error
while preserving the original result. Older results without a prepared record
retain their behavior. This is explicit module retention, with no implicit
capture added to other tools. No new descriptor option or public Rust DTO field
is introduced. The additive format is documented in `docs/modules.md` and
`RELEASING.md`.

The document distinguishes preparation from provider delivery and module input
from adapter transformations. Neither the record nor later reading establishes
successful discovery, a true positive, a fix or exact consumption. Cancellation
is checked again after retention and before runtime entry. Existing typed errors,
model selection and allowance behavior remain intact.

There are 131 distinct focused Rust passes, a passing workspace build and ten
passing final summary gates. The risk proxy passes for 401 changed code files.
The complete registry and visible catalog remain byte-identical: 189 registered
actions and 118 visible, with 81 Core, 32 Labs and five Compatibility actions.

Final sequential tmux journeys J319 and J318 have 85 machine passes, zero
failures and 82 capture pairs. Nine human judgments remain pending for this
pair; earlier source-review and learning judgments are not closed by it.
All 4503 source inputs, 776 runtime inputs and thirteen frozen programs remain
unchanged through the pair. Native SHA256:
`e731ad8a6426a2db0dffac52d82d5606235d917eead8ba6452e1e7dc0167e8c3`.

J319 intercepts one refused request and one paused request. The provider fixture
checks that the original runtime prompt is already retained before fetch.
The crash helper confirms the executable and exact canonical target before
killing only its owned test shell. Restart recovers the second request's exact
document. Both calls remain committed. The refused request is settled with incomplete
cost; the interrupted reservation remains unsettled. No observation or human
decision is invented, and protected Review capacity remains unused. Failure shows cost
unavailable; interruption shows cost not recorded. Neither is shown as zero
known consumption. All six sizes and no-color restart are covered.

J318 retains its three separately invoked intercepted requests, partial source,
one published observation, human FP decision and protected Review capacity.
It checks successful Result/Inputs reading, withheld publication, exhaustion,
narrow paging and restart. The final pair uses five intercepted requests and
zero live provider requests. It does not establish real-model detection quality.

Two earlier J319 attempts remain preserved. The first incorrectly expected
Saved Output, although failures intentionally open Summary. Inspection also
found and fixed a real heading defect: Summary said Tab receipt while the
footer offered Tab inputs. A regression fixture initially paired a blocked
call with a failed result; the reader correctly refused it. That fixture now
records a genuine failed call. The next native attempt stopped before sending
a signal because its string comparison confused `/tmp` with `/private/tmp`.
The corrected guard resolves the complete `--target` argument and records its
identity proof. A separate import-order gate failure and all earlier logs remain
available. No failed check was suppressed.

Eighty-two ANSI cell replays were generated; fourteen were inspected, including
all six retained-input sizes and no-color recovery. These are terminal-cell
renderings, not OS screenshots or human acceptance. Dense scope references,
repeated provider error text, narrow notice/chrome overhead and accepted scope
and allowance visibility still need refinement. Reference parity remains
unqualified. Other adapters' source binding and input retention, large repository
support, eight hidden Core action audits and all nine broad milestones remain open.

Publication stays **Keep as draft** on `main`. The original seven-file index
and saved 366-file proposal remain intact. No project commit, push or live
request is added. Fourteen live experiment requests are spent, with no live
allowance remaining. Evidence:
`/tmp/kuzushi-prepared-input-recovery-20261016`.
