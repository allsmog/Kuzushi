// /story · narrate this run as a triage memo. Long-form prose output.

function StoryView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function line(text, c) { return window.row([T('   '), [text, c || 'c-primary']], W, text.slice(0,12)); }

  const lines = [
    window.logLine('in','14:46:01',[m(' /story '), a('--audience triage --since 2h')], W, 'l1'),
    window.logLine('run','14:46:01',[m(' narrator '), p('anthropic:claude-haiku'), m(' · 38 findings · 6 runs · 1 patch')], W, 'l2'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), ['── MEMO · acme-checkout · 2 hours of kuzushi ', 'c-label'],
      ['─'.repeat(W - 2 - 46), 'c-subtle']], W, 'memo'),
    window.blankRow(W, 'b2'),
    line('TL;DR', 'c-warn'),
    line('Two CRITICAL prompt-injection sinks (F-0002, F-0012) and a SQL injection (F-0001) cluster around'),
    line('the same review-handler in /apps/web. F-0012 is a $-loss path — the refund-bot can issue refunds'),
    line('under $200 without a human approver, and the injection lets a reviewer override that threshold.'),
    line('We have a verified PoC for F-0001 and F-0012; F-0002 is plausible but unverified.'),
    window.blankRow(W, 'b3'),
    line('What we ran', 'c-warn'),
    line(' · /scan (umbrella) · 14:31 · semgrep, secret-scan, agentic-sast, triage  · $0.41 · 38 promoted'),
    line(' · /use threat-model · 14:18 · PASTA + STRIDE · 9 trust boundaries · 21 attacker stories'),
    line(' · /use carlini · 14:08 · h=2 · 12 frames · 1 high-confidence finding (F-0012)'),
    line(' · /use verify F-0001 · 14:36 · sqlmap PoC against ephemeral pg · OK'),
    line(' · /use patch F-0002 · 14:30 · staged · checks 4/5 · verify rerun pending'),
    window.blankRow(W, 'b4'),
    line('Top 3 recommendations', 'c-warn'),
    line(' 1. Apply patch F-0002 + verify rerun (5 min — staged hunks pass typecheck and the new test).'),
    line(' 2. Lift F-0012 ($-loss prompt-injection) above F-0003 in the queue. Same fix shape as F-0002,'),
    line('    plus drop the per-actor refund cap to $0 until reviewed by humans.'),
    line(' 3. Treat the entire `apps/web/agents` cluster as a single trust boundary. Three findings within'),
    line('    six lines suggests the abstraction is wrong, not the call site.'),
    window.blankRow(W, 'b5'),
    line('What we did NOT do (and why)', 'c-warn'),
    line(' · Did not run codeql · binary missing · refused per policy (no silent fallback).'),
    line(' · Did not exercise refund.acme prod · network egress confirm dialog · operator declined.'),
    line(' · Did not auto-apply the F-0002 patch · approval.patches = human-required (project policy).'),
    window.blankRow(W, 'b6'),
    line('Audit pointers', 'c-warn'),
    line(' · runs at .kuzushi/runs/r-2110..r-2115/   · ~2.4 MB total'),
    line(' · audit log .kuzushi/v2/audit.log         · 14 entries this session'),
    line(' · findings  .kuzushi/v2/findings.sqlite3  · 38 rows (11 high+, 7 medium, 20 low/info)'),
    window.blankRow(W, 'b7'),
    window.logLine('flow','14:46:18',[m(' '), [' suggested ', 'c-success'], m(' '), a('/story --format markdown > memo.md'),
      m(' · '), a('/story --thread'), m(' for slack-format')], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · /story · triage memo">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'narrator', cost: '$0.07' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'story · triage memo · ~420 words', findings: 38,
        promptModule: 'narrator',
        keybinds: [['--audience','triage|exec|dev'],['--format','markdown|thread'],['/save','memo.md']],
      })}
    </window.TermFrame>
  );
}
window.StoryView = StoryView;
