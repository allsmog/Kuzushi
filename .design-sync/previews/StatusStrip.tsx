import { TermFrame, StatusStrip } from "@kuzushi/tui-kit";

// A populated strip: target, fresh context, model, active module, running cost.
export function Active() {
  return (
    <TermFrame chromeless cols={112}>
      <StatusStrip
        target="~/work/acme-checkout"
        ctx="fresh (3m ago)"
        model="openai:gpt-4.1"
        module="sast"
        cost="$0.41"
        cols={112}
      />
    </TermFrame>
  );
}

// No module selected yet — the `module` field falls back to a muted dash.
export function NoModule() {
  return (
    <TermFrame chromeless cols={112}>
      <StatusStrip target="~/scan/payments-api" ctx="fresh" cost="$0.00" cols={112} />
    </TermFrame>
  );
}
