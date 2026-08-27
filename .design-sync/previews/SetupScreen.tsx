import { SetupScreen } from "@kuzushi/tui-kit";

const facts = [
  { label: "repository", value: "git · branch codex/atlas-native-cockpit" },
  { label: "revision", value: "ccb29fa · dirty no" },
  { label: "files", value: "1,842 · Rust, TypeScript, Markdown" },
  { label: "build", value: "Cargo workspace · pnpm" },
  { label: "scope", value: "root target · 3 nested workspaces" },
  { label: "prior", value: "6 findings · 4 run receipts" },
] as const;

export const A_ReadySetup120x36 = () => (
  <SetupScreen
    target="/workspace/Kuzushi"
    readiness={[
      { id: "target", label: "Target", status: "CONFIRMED", detail: "Kuzushi · ccb29fa · clean", tone: "ready" },
      { id: "plan", label: "Map plan", status: "READY", detail: "2 deterministic tasks selected", tone: "ready" },
      { id: "model", label: "Model", status: "OPTIONAL", detail: "selected plan is runtime-free", tone: "optional" },
      { id: "credentials", label: "Credentials", status: "OPTIONAL", detail: "not required by selected tasks", tone: "optional" },
      { id: "prompt", label: "Prompt", status: "DEFAULT", detail: "descriptor prompt in effect", tone: "optional" },
      { id: "budget", label: "Budget", status: "NOT ENFORCED", detail: "no operator cap set", tone: "optional" },
      { id: "start", label: "Start Map", status: "READY", detail: "commit this engagement", tone: "action", selected: true },
    ]}
    facts={facts}
    action={{ ready: true, selectedTasks: 2, label: "Start Map" }}
    cols={120}
    rows={36}
  />
);

export const B_ModelAndCredentialBlocked80x24 = () => (
  <SetupScreen
    target="/workspace/Kuzushi"
    readiness={[
      { id: "target", label: "Target", status: "CONFIRMED", detail: "Kuzushi · ccb29fa · clean", tone: "ready" },
      { id: "plan", label: "Map plan", status: "READY", detail: "context:build + threat-model:build", tone: "ready" },
      { id: "model", label: "Model", status: "EXPLICIT", detail: "openai:gpt-5.4 selected", tone: "ready" },
      { id: "credentials", label: "Credentials", status: "MISSING", detail: "selected model requires OpenAI authentication", tone: "blocked", selected: true },
      { id: "prompt", label: "Prompt", status: "DEFAULT", detail: "descriptor prompt in effect", tone: "optional" },
      { id: "budget", label: "Budget", status: "$2.00 CAP", detail: "within the hard ceiling", tone: "ready" },
      { id: "start", label: "Start Map", status: "BLOCKED", detail: "resolve Credentials first", tone: "action" },
    ]}
    action={{ ready: false, selectedTasks: 2, label: "Start Map" }}
    cols={80}
    rows={24}
  />
);

export const C_CompactSetup40x12 = () => (
  <SetupScreen
    target="./Kuzushi"
    readiness={[
      { id: "target", label: "Target", status: "CONFIRMED", detail: "Kuzushi · ccb29fa", tone: "ready" },
      { id: "plan", label: "Map plan", status: "READY", detail: "2 tasks", tone: "ready" },
      { id: "model", label: "Model", status: "OPTIONAL", detail: "runtime-free", tone: "optional" },
      { id: "credentials", label: "Credentials", status: "OPTIONAL", detail: "not required", tone: "optional" },
      { id: "start", label: "Start Map", status: "READY", detail: "commit engagement", tone: "action", selected: true },
    ]}
    action={{ ready: true, selectedTasks: 2, label: "Start Map" }}
    cols={40}
    rows={12}
  />
);
