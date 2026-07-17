# Durable shell session transcripts

Kuzushi records each shell launch as a global, operator-owned semantic
transcript. The transcript answers session-level causality questions such as
which target was selected, which commands ran, which run produced a result,
and whether the shell exited cleanly.

## Storage and ownership

Transcripts live outside scanned repositories:

```text
~/.kuzushi/v3/sessions/YYYY/MM/DD/session-<timestamp>-<uuid>.jsonl
```

Directories are created with mode `0700` and files with mode `0600` on Unix.
Kuzushi refuses symlinked transcript destinations. The JSONL is authoritative;
there is no database or index in v1.

This store is deliberately distinct from:

- `<target>/.kuzushi/v3/shell-history.txt`, the bounded command-completion
  history for one target;
- `<target>/.kuzushi/v3/runs/<runId>/`, the detailed input, result, trace, and
  replay artifacts for one execution;
- `<target>/.kuzushi/v3/log`, the finding/workflow projection event log; and
- the shell Logs view, a bounded in-memory projection that may be cleared.

One transcript can begin targetless and can record later target changes. Run
events carry `runId` references instead of copying large run payloads.

## Record contract

Each line uses schema version 1 and contains:

```json
{
  "schemaVersion": 1,
  "timestamp": "RFC3339",
  "sessionId": "uuid",
  "sequence": 0,
  "eventId": "uuid",
  "parentEventId": null,
  "type": "session_meta",
  "payload": {}
}
```

`session_meta` is always the first record. It identifies shell mode, cwd,
sanitized argv, Kuzushi build, process identity, Git revision when available,
the initial target, and how that target was supplied. Later records cover
submitted commands, target and major-view changes, operator-visible notices,
run lifecycle, operator questions and answers, visible agent turns, attachment
references, persistence warnings, and session completion.

Keystrokes, terminal resize/mouse/tick events, streaming token deltas, hidden
reasoning, environment values, and credential entry are never transcript
events. Existing run artifacts remain the detailed execution record.

## Privacy and boundedness

Redaction happens before serialization. Secret-bearing JSON keys, credential
question content, authorization headers, common token shapes, and secret CLI
arguments are replaced with `[REDACTED]`. Git remote credentials are removed.
An individual record is capped at 1 MiB; oversized records become a truncation
record containing only the original byte count and a digest.

Transcripts can still contain operator prompts, visible model answers, source
paths, and ordinary command text. Treat the directory as sensitive local
operator data and review an export before sharing it.

## Writer and failure behavior

A single background writer owns the append-only file. It consumes a bounded
queue, writes one JSON object plus newline, flushes semantic boundaries, and
retains unwritten records for reopen-and-retry after filesystem failures.
Recording failures do not change the selected model, runtime, tool, or target
and do not stop the shell. Kuzushi surfaces a persistent warning and exposes
writer health through the `session` shell command.

A clean exit writes `session_end`. A transcript without that event is reported
as `running` only while the recorded process identity is still alive;
otherwise it is `interrupted`.

## Retention and controls

Session recording is on for interactive, plain, and scripted shell launches.
`kuzushi run` and `kuzushi scan` keep their existing run-artifact contracts and
do not create shell transcripts.

The global operator config controls retention:

```toml
[operator]
session_retention_days = 30
```

Project-local config cannot set this value. Startup cleanup and `kuzushi
sessions prune` skip live sessions. A single shell launch may opt out with
`--no-session-persistence` (alias `--ephemeral`); target run artifacts are not
disabled by that flag.

Use `kuzushi sessions list`, `show`, `export`, and `prune` to inspect or manage
the store. Resume from a transcript is intentionally outside the v1 contract.
