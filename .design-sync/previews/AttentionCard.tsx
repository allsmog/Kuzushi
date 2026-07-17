import { AttentionCard, TerminalFrame } from "@kuzushi/tui-kit";

const Frame = ({ children, title = "attention" }: { children: React.ReactNode; title?: string }) => (
  <TerminalFrame title={`kuzushi · ${title}`} cols={80} rows={24} chromeless>
    <div className="kz-screen">
      <div>KUZUSHI · VIEW PROVE · target ./phase-target · ○ idle · ctx:✓ built</div>
      <div>▸ NEXT answer the operator question to resume verification</div>
      <div style={{ flex: 1 }} />
      {children}
    </div>
  </TerminalFrame>
);

export const A_OperatorQuestion = () => (
  <Frame title="waiting input">
    <AttentionCard
      kind="question"
      title="Which authenticated role should verification use?"
      body="The run is paused safely. Choose a recorded test identity; no request will be sent until you answer."
      detail="source: verify:finding F-0002 · target ./phase-target · run verify-f0002"
      choices={[
        { key: "1", label: "standard user", detail: "recommended · recorded fixture user-17" },
        { key: "2", label: "support agent", detail: "recorded fixture support-3" },
        { key: "o", label: "Other", detail: "enter a different fixture identity" },
      ]}
      controls={[
        { key: "j/k", label: "move" },
        { key: "Enter", label: "submit" },
        { key: "Esc", label: "cancel run" },
      ]}
    />
  </Frame>
);

export const B_Confirmation = () => (
  <Frame title="confirmation">
    <AttentionCard
      kind="confirmation"
      title="Accept this partial Scan attempt?"
      body="Semgrep and tree-sitter completed. CodeQL did not run because its binary is unavailable."
      detail="Accepting records a partial attempt; it does not claim CodeQL coverage or a complete cost."
      choices={[
        { key: "y", label: "accept partial", detail: "continue to Review with explicit degradation" },
        { key: "n", label: "keep Scan current", detail: "inspect Jobs or retry the missing engine" },
      ]}
      controls={[
        { key: "y/n", label: "decide" },
        { key: "t", label: "trace" },
      ]}
    />
  </Frame>
);

export const C_CredentialGate = () => (
  <Frame title="credentials">
    <AttentionCard
      kind="credential"
      title="OpenAI authentication is required by the selected model"
      body="Kuzushi will not switch provider, model, or runtime automatically."
      detail="model openai:gpt-5.4 · selected by Setup · key material remains hidden"
      choices={[
        { key: "1", label: "stored OAuth session", detail: "not found" },
        { key: "2", label: "API key", detail: "enter securely; value is never displayed" },
        { key: "3", label: "return to Setup", detail: "choose a runtime-free plan or another explicit model" },
      ]}
      selected={1}
      controls={[
        { key: "Enter", label: "choose" },
        { key: "Esc", label: "back" },
      ]}
    />
  </Frame>
);

export const D_ToolApproval = () => (
  <Frame title="approval">
    <AttentionCard
      kind="approval"
      title="Approve patch application for F-0001?"
      body="Apply the staged parameterized-query diff to routes/login.rs."
      detail="actor patch:finding · target ./phase-target · writes 1 file · no shell allowlist expansion"
      choices={[
        { key: "y", label: "approve once", detail: "apply this exact staged digest" },
        { key: "n", label: "deny", detail: "retain the staged patch without modifying the target" },
      ]}
      controls={[
        { key: "v", label: "view diff" },
        { key: "y/n", label: "decide" },
      ]}
    />
  </Frame>
);
