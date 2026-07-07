import { TermFrame, LogLine, Glyph, SeverityBadge } from "@kuzushi/tui-kit";

// Every line kind, the primary variant axis — glyph + tone per kind.
export function Kinds() {
  return (
    <TermFrame chromeless cols={84}>
      <LogLine kind="in" time="14:31:55">{" /scan"}</LogLine>
      <LogLine kind="run" time="14:31:55">
        {" sast:scan · tasks "}
        <Glyph tone="accent">semgrep, secrets</Glyph>
      </LogLine>
      <LogLine kind="ok" time="14:32:40">
        {" semgrep · 612/612 · "}
        <Glyph tone="success">done</Glyph>
      </LogLine>
      <LogLine kind="agent" time="14:33:42">
        {" two CRITICALs share a sink at "}
        <Glyph tone="warn">orders.rs:142</Glyph>
      </LogLine>
      <LogLine kind="flow" time="14:33:48">{" tracing dataflow…"}</LogLine>
      <LogLine kind="find" time="14:33:42">
        {" "}
        <Glyph tone="primary">F-0012</Glyph>
        {" · "}
        <SeverityBadge level="critical" />
      </LogLine>
      <LogLine kind="err" time="15:46:01">
        {" "}
        <Glyph tone="danger"> HARD STOP </Glyph>
        {" · run budget reached"}
      </LogLine>
      <LogLine kind="log" time="15:46:02">{" autosaved run a3f1 to .kuzushi/runs"}</LogLine>
    </TermFrame>
  );
}

// A realistic transcript slice — how the lines read in sequence.
export function Transcript() {
  return (
    <TermFrame chromeless cols={84}>
      <LogLine kind="in" time="14:33:40">{" /use verify"}</LogLine>
      <LogLine kind="run" time="14:33:40">{" verify:finding · F-0001 · taint-iris"}</LogLine>
      <LogLine kind="agent" time="14:33:51">
        {" reachable: user "}
        <Glyph tone="accent">order_id</Glyph>
        {" flows unsanitized into the query string"}
      </LogLine>
      <LogLine kind="ok" time="14:34:02">
        {" F-0001 "}
        <Glyph tone="success">verified exploitable</Glyph>
        {" · poc written"}
      </LogLine>
    </TermFrame>
  );
}
