import { TermFrame, Heatmap } from "@kuzushi/tui-kit";

// The core module × severity grid — where is the risk concentrated?
export function RiskByModule() {
  return (
    <TermFrame chromeless cols={72}>
      <Heatmap
        cols={64}
        modules={[
          { name: "payments", counts: { critical: 2, high: 3, medium: 1 } },
          { name: "auth", counts: { high: 1, medium: 2, low: 4 } },
          { name: "reports", counts: { medium: 1, info: 6 } },
          { name: "api", counts: { critical: 1, high: 2, low: 1 } },
        ]}
      />
    </TermFrame>
  );
}

// A busier grid across more modules — bar-width scaling under load.
export function BusyGrid() {
  return (
    <TermFrame chromeless cols={80}>
      <Heatmap
        title="FINDINGS HEATMAP · 74 across 7 modules"
        cols={72}
        modules={[
          { name: "checkout", counts: { critical: 4, high: 6, medium: 3, low: 2 } },
          { name: "session", counts: { high: 2, medium: 5, low: 8 } },
          { name: "webhooks", counts: { critical: 1, high: 1 } },
          { name: "uploads", counts: { high: 3, medium: 2, low: 1, info: 4 } },
          { name: "billing", counts: { medium: 7, low: 3 } },
          { name: "admin", counts: { critical: 2, high: 1, medium: 1 } },
          { name: "search", counts: { low: 5, info: 9 } },
        ]}
      />
    </TermFrame>
  );
}
