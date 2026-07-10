import { TermFrame, DataFlowLadder } from "@kuzushi/tui-kit";

// A SQL-injection taint flow, source → hop → sink, all reached ✓.
export function SqlInjectionReached() {
  return (
    <TermFrame chromeless cols={72}>
      <DataFlowLadder
        title="CWE-89 · SQL Injection"
        legs={[
          { kind: "source", label: "req.body.id", note: "handler.ts:20", reached: true },
          { kind: "hop", label: "buildQuery()", note: "sql.ts:44", reached: true },
          { kind: "sink", label: "db.exec()", note: "db.ts:9", reached: true },
        ]}
      />
    </TermFrame>
  );
}

// A sanitizer hop breaks the chain — the last leg is never reached.
export function SanitizedStops() {
  return (
    <TermFrame chromeless cols={76}>
      <DataFlowLadder
        title="CWE-79 · XSS (mitigated)"
        legs={[
          { kind: "source", label: "req.query.q", note: "search.ts:12", reached: true },
          { kind: "hop", label: "escapeHtml()", note: "sanitize.ts:31", reached: true },
          { kind: "sink", label: "res.send(html)", note: "render.ts:58", reached: false },
        ]}
      />
    </TermFrame>
  );
}
