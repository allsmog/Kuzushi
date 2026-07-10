import { TermFrame, AttackPath } from "@kuzushi/tui-kit";

// A SQL-injection taint flow, source → sink, critical. The primary story.
export function SqlInjection() {
  return (
    <TermFrame chromeless cols={72}>
      <AttackPath
        cwe="CWE-89"
        severity="critical"
        stages={[
          { label: "req.body.id" },
          { label: "buildQuery" },
          { label: "db.exec" },
        ]}
      />
    </TermFrame>
  );
}

// A longer SSRF chain — the stage-count axis, high severity.
export function Ssrf() {
  return (
    <TermFrame chromeless cols={84}>
      <AttackPath
        cwe="CWE-918"
        severity="high"
        stages={[
          { label: "webhook.url" },
          { label: "normalize" },
          { label: "fetch" },
          { label: "metadata" },
        ]}
      />
    </TermFrame>
  );
}
