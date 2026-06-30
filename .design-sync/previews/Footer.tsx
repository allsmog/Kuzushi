import { TermFrame, Row, Footer } from "@kuzushi/tui-kit";

// Mid-scan: a live stage, findings on the board, and the view's keybind contract.
export function Active() {
  return (
    <TermFrame chromeless cols={90}>
      <Row cols={90}>{" … scan in progress"}</Row>
      <Footer
        stage="sast:scan · agentic 73%"
        findings={11}
        module="sast"
        keybinds={[
          { key: "/findings", hint: "browse" },
          { key: "/open", hint: "F-0001" },
          { key: "/use", hint: "verify" },
          { key: "/pause", hint: "halt scan" },
        ]}
        cols={90}
      />
    </TermFrame>
  );
}

// Idle: no module, zero findings, the bare prompt.
export function Idle() {
  return (
    <TermFrame chromeless cols={90}>
      <Row cols={90}>{" ready"}</Row>
      <Footer
        stage="idle"
        findings={0}
        keybinds={[
          { key: "/scan", hint: "start" },
          { key: "/use", hint: "module" },
          { key: "/help", hint: "keybinds" },
        ]}
        cols={90}
      />
    </TermFrame>
  );
}
