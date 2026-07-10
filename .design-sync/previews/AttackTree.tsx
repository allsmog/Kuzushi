import { TermFrame, AttackTree } from "@kuzushi/tui-kit";

// An OR-gated goal: any one of several chains reaches customer PII.
export function StealPii() {
  return (
    <TermFrame chromeless cols={80}>
      <AttackTree
        goal="steal customer PII"
        impact="account takeover"
        gate="OR"
        chains={[
          {
            label: "SQLi in /search → dump users",
            severity: "critical",
            steps: ["unauthenticated endpoint", "error-based extraction"],
          },
          {
            label: "IDOR on /invoice → cross-tenant read",
            severity: "high",
            steps: ["sequential invoice ids", "missing owner check"],
          },
          { label: "verbose stack trace → schema leak", severity: "medium" },
        ]}
        moreChains={2}
      />
    </TermFrame>
  );
}

// An AND-gated goal: every step is required to reach the goal.
export function AccountTakeover() {
  return (
    <TermFrame chromeless cols={80}>
      <AttackTree
        goal="admin account takeover"
        impact="full tenant compromise"
        gate="AND"
        chains={[
          {
            label: "leaked JWT signing key",
            severity: "critical",
            steps: ["key committed to git history"],
          },
          {
            label: "forge admin session token",
            severity: "high",
            steps: ["no audience claim check", "long-lived expiry"],
          },
        ]}
      />
    </TermFrame>
  );
}
