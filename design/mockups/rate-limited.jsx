// model rate-limited · graceful fallback

function RateLimitedView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  const lines = [
    window.logLine('err','16:04:01',[m(' '), [' RATE LIMIT ', 'c-warn'],
      m(' · '), p('anthropic'), m(' returned '), p('429'),
      m(' · retry-after '), p('14s'),
      m(' · this is the '), p('3rd'), m(' 429 in '), p('5min')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('SCOPE · who is affected', W, 's1'),
    window.row([T('   '), [' ⏵ ', 'c-warn'], m('  '), p('agentic-sast'),
      m('   r-2118 · paused at frame 41/64 · '), [' resumable ', 'c-success']], W, 'sc1'),
    window.row([T('   '), [' ⏵ ', 'c-warn'], m('  '), p('chat'),
      m('           streaming response halted at '), p('212/~480 tok'),
      m(' · '), [' resumable ', 'c-success']], W, 'sc2'),
    window.row([T('   '), [' · ', 'c-subtle'], m('  '), p('verify'),
      m('         unaffected · sandbox runs locally')], W, 'sc3'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('WHY · the 429 in detail', W, 's2'),
    window.row([T('   '), m('header    '), p('retry-after: 14s')], W, 'w1'),
    window.row([T('   '), m('limit-key '), p('input-tokens-per-minute · org acme-llc')], W, 'w2'),
    window.row([T('   '), m('used      '), p('1.42M / 1.40M cap (101%)'),
      m(' · '), [' over by 21k ', 'c-warn']], W, 'w3'),
    window.row([T('   '), m('cause     '), p('attacker actor on r-2118 · 1.18M alone'),
      m(' · large fs:read of generated test files (concierge.test.ts × 14)')], W, 'w4'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('AUTOMATIC RESPONSE · already happening', W, 's3'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('paused both'),
      m(' affected runs · checkpointed at frame 41 / 212 tok')], W, 'a1'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('exponential backoff'),
      m(' armed · 14s · 28s · 56s · 90s')], W, 'a2'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('audit row'),
      m(' written · audit.log:1862 op=llm:rate-limited actor=attacker')], W, 'a3'),
    window.row([T('   '), [' · ', 'c-subtle'], m('  '), p('budgets'),
      m('       unchanged · this is a temporary network event')], W, 'a4'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('YOUR OPTIONS', W, 's4'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), a('w'),
      m(' wait & auto-resume        '), m('   default · ~ 14s · uses backoff')], W, 'o1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), a('s'),
      m(' switch to backup model    '), m('   '), p('openai:gpt-4.1-mini'),
      m(' for the rest of these turns · resume after')], W, 'o2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), a('r'),
      m(' route per-actor          '), m('     '), p('attacker → openai'),
      m('  ·  '), p('critic → anthropic'),  m('  (mix)')], W, 'o3'),
    window.row([T('   '), [' 4 ', 'c-accent'], m('  '), a('e'),
      m(' edit budget plan         '), m('     /budget --tokens 800k/min')], W, 'o4'),
    window.row([T('   '), [' 5 ', 'c-accent'], m('  '), a('n'),
      m(' stop and triage          '), m('     keep partial findings, /use triage F-0044')], W, 'o5'),
    window.blankRow(W, 'b5'),
    window.row([T('   '), m('default in '), p('14s'),
      m(' · '), [' w · wait & auto-resume ', 'c-success']], W, 'def'),
  ];

  return (
    <window.TermFrame title="kuzushi · model rate-limited · 429">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'agentic-sast', cost: '$2.50' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'rate-limit · 429 · backoff armed · 14s', findings: 38,
        promptModule: 'agentic-sast',
        keybinds: [['w','wait'],['s','switch model'],['r','route'],['n','triage']],
      })}
    </window.TermFrame>
  );
}
window.RateLimitedView = RateLimitedView;
