// first-run / onboarding.

function OnboardingView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function step(n, done, title, body) {
    const dot = done ? [' ✓ ', 'c-success'] : [' · ', 'c-subtle'];
    const out = [];
    out.push(window.row([T('  '), dot, [String(n) + '. ', 'c-muted'], [title, done ? 'c-muted' : 'c-primary']], W, 't'+n));
    for (const b of body) out.push(window.row([T('       '), [b, 'c-muted']], W, 't'+n+b));
    return out;
  }

  const lines = [
    window.row([T('   '), ['┌─ ', 'c-subtle'], ['welcome to kuzushi · v0.18.2 ', 'c-heading'],
      ['─'.repeat(W - 6 - 28), 'c-subtle'], ['┐', 'c-subtle']], W, 'top'),
    window.row([T('   '), ['│ ', 'c-subtle'], [' a ratatui shell for security agents · five minutes from clone to first finding'.padEnd(W - 8, ' '), 'c-primary'], [' │', 'c-subtle']], W, 'r1'),
    window.row([T('   '), ['└', 'c-subtle'], ['─'.repeat(W - 6), 'c-subtle'], ['┘', 'c-subtle']], W, 'bot'),
    window.blankRow(W, 'b1'),
    ...step(1, true, 'install', [
      'cargo install kuzushi  ·  homebrew install kuzushi  ·  curl … | sh',
      'binary in $PATH as `kuzushi`',
    ]),
    ...step(2, true, 'point at a workspace', [
      'kuzushi ~/work/acme-checkout',
      'creates .kuzushi/v2/ · index, runs, findings, audit log',
    ]),
    ...step(3, false, 'connect a model · /auth', [
      'minimum: one provider with a chat model.',
      'works with openai, anthropic, google, local (ollama).',
      '/auth login anthropic   · the recommended starter actor for offense',
    ]),
    ...step(4, false, 'first guided run · /full', [
      'umbrella sast: semgrep + secret-scan + agentic-sast + triage.',
      'budget caps default to $5/run · pause/resume any time.',
    ]),
    ...step(5, false, 'narrate · /story', [
      'render the run as a triage memo for the next reviewer.',
      'persists alongside the findings.',
    ]),
    window.blankRow(W, 'b2'),
    window.sectionHeader('OPTIONAL', W, 's1'),
    window.row([T('   '), [' · ', 'c-subtle'], m('install codeql ('), p('brew install codeql'), m(') if you want CodeQL coverage')], W, 'opt1'),
    window.row([T('   '), [' · ', 'c-subtle'], m('install firejail or docker for sandboxed sandbox:run')], W, 'opt2'),
    window.row([T('   '), [' · ', 'c-subtle'], m('point '), p('KUZUSHI_TOB_SKILLS_DIR'), m(' at '), p('~/plugins/tob/skills'), m(' for ToB audits')], W, 'opt3'),
    window.row([T('   '), [' · ', 'c-subtle'], m('point '), p('KUZUSHI_SHINSA_PLUGIN'), m(' for ISO/NIST/SOC2 scans')], W, 'opt4'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('TELEMETRY', W, 's2'),
    window.row([T('   '), [' ✗ ', 'c-danger'], m('  '), p('OFF'), m(' by default · no run data ever leaves your box')], W, 'tl1'),
    window.row([T('   '), [' i ', 'c-accent'], m('  to opt in: '), a('/setg telemetry on'),
      m(' · sends '), p('module name, latency, refusal rate'), m(' only · '), p('never'), m(' source / findings')], W, 'tl2'),
    window.blankRow(W, 'b4'),
    window.row([T('  '), [' ▸ NEXT  ', 'c-warn'], [m('Run '), null], [a('/auth login anthropic'), null],
      [m(' · I will pick up where you stopped'), null]], W, 'next'),
  ];

  return (
    <window.TermFrame title="kuzushi · first run">
      <span className="row" key="strip">{' KUZUSHI · target=~/work/acme-checkout · ctx=building (first run) · model=— · cost=$0.00                     '}</span>
      <span className="row c-subtle" key="rule">{'─'.repeat(W)}</span>
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'onboarding · step 3 of 5', findings: 0,
        keybinds: [['/auth','login'],['/full','guided run'],['?','help'],['Ctrl+C','quit']],
      })}
    </window.TermFrame>
  );
}
window.OnboardingView = OnboardingView;
