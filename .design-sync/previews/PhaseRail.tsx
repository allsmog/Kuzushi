import { TermFrame, PhaseRail } from "@kuzushi/tui-kit";

// The engagement spine mid-hunt — 組 map done, 崩 hunt current (warn + ●,
// upper-cased), 作 confirm / 掛 fix still pending. The primary on-path axis.
export function Engagement() {
  return (
    <TermFrame chromeless cols={72}>
      <PhaseRail
        cols={72}
        phases={[
          { kanji: "組", label: "map", state: "done" },
          { kanji: "崩", label: "hunt", state: "current" },
          { kanji: "作", label: "confirm", state: "pending" },
          { kanji: "掛", label: "fix", state: "pending" },
        ]}
      />
    </TermFrame>
  );
}

// Off-path reality — the map phase failed (! danger) so the rail refuses to
// fabricate progress; confirm is skipped (⊘ muted) while fix is the current
// band. Shows the failed/skipped honesty axis alongside done/current.
export function OffPath() {
  return (
    <TermFrame chromeless cols={72}>
      <PhaseRail
        cols={72}
        phases={[
          { kanji: "組", label: "map", state: "failed" },
          { kanji: "崩", label: "hunt", state: "done" },
          { kanji: "作", label: "confirm", state: "skipped" },
          { kanji: "掛", label: "fix", state: "current" },
        ]}
      />
    </TermFrame>
  );
}
