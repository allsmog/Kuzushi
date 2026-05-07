// prompt-armor · red-flag finding

function PromptArmorRedFlagView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function row(focused, id, sev, name, surface, ttp) {
    const sevMap = { critical:'c-sev-critical', high:'c-sev-high', medium:'c-sev-medium' };
    const idCell = (id + ' '.repeat(10)).slice(0, 8);
    const sCell = (sev.toUpperCase() + ' '.repeat(10)).slice(0, 9);
    const nCell = (name + ' '.repeat(60)).slice(0, 50);
    const surCell = (surface + ' '.repeat(28)).slice(0, 26);
    if (focused) {
      const text = ' ' + idCell + sCell + nCell + surCell + ttp;
      return <span className="row" key={id}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([
      ['    ', null],
      [idCell, 'c-accent'],
      [sCell, sevMap[sev]],
      [nCell, 'c-primary'],
      [surCell, 'c-muted'],
      [ttp, 'c-muted'],
    ], W, id);
  }

  const lines = [
    window.logLine('in','15:18:01',[m(' /run prompt-armor:matrix '), a('{"agents":"apps/web/agents/*"}')], W, 'l1'),
    window.logLine('run','15:18:01',[m(' loading attack ttps · '), p('a-04 prompt-injection'),
      m(' · '), p('a-08 indirect injection'), m(' · '), p('a-13 jailbreak'),
      m(' · '), p('a-21 tool-misuse'), m(' · '), p('a-29 sysprompt-extract')], W, 'l2'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), ['╔══ RED FLAG ', 'c-danger'],
      ['═'.repeat(W - 4 - 12 - 1), 'c-danger'], ['╗', 'c-danger']], W, 'top'),
    window.row([T('   '), ['║ ', 'c-danger'],
      [' refund-bot accepts review.body in sysmsg AND has a money-moving tool. This is the canonical $-loss '.padEnd(W - 8, ' '), 'c-primary'],
      [' ║', 'c-danger']], W, 'r1'),
    window.row([T('   '), ['║ ', 'c-danger'],
      [' shape from a-04 + a-21. Treat as exploitable until verified otherwise.'.padEnd(W - 8, ' '), 'c-primary'],
      [' ║', 'c-danger']], W, 'r2'),
    window.row([T('   '), ['╚', 'c-danger'], ['═'.repeat(W - 6), 'c-danger'], ['╝', 'c-danger']], W, 'bot'),
    window.blankRow(W, 'b2'),
    window.row([
      ['    ', null],
      [('id' + ' '.repeat(8)).slice(0, 8), 'c-label'],
      [('sev' + ' '.repeat(9)).slice(0, 9), 'c-label'],
      [('issue' + ' '.repeat(50)).slice(0, 50), 'c-label'],
      [('surface' + ' '.repeat(26)).slice(0, 26), 'c-label'],
      ['ttp', 'c-label'],
    ], W, 'h'),
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'rule'),
    row(true,  'F-0012', 'critical', 'review.body in sysmsg + refund tool',          'refund-bot.ts:127',          'a-04 + a-21'),
    row(false, 'F-0002', 'critical', 'review.body in sysmsg (concierge)',            'concierge.ts:88',            'a-04'),
    row(false, 'F-0019', 'high',     'tool-name reflection (model picks tool by str)','concierge.ts:142',          'a-21'),
    row(false, 'F-0024', 'high',     'sysprompt-extract via base64 prefix attack',   'apps/web/agents/orch.ts:64', 'a-29'),
    row(false, 'F-0028', 'medium',   'jailbreak: "DAN-style" prefix accepted',       'concierge.ts:102',           'a-13'),
    row(false, 'F-0033', 'medium',   'indirect injection via redis blob',            'jobs/worker.py:184',         'a-08'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('TTP COVERAGE · 14 / 32', W, 's1'),
    window.row([T('   '), p('a-04'), m('   prompt-injection      '), [' covered (3 hits) ', 'c-danger']], W, 't1'),
    window.row([T('   '), p('a-08'), m('   indirect injection    '), [' covered (1 hit) ', 'c-warn']], W, 't2'),
    window.row([T('   '), p('a-13'), m('   jailbreak              '), [' covered (1 hit) ', 'c-warn']], W, 't3'),
    window.row([T('   '), p('a-21'), m('   tool-misuse            '), [' covered (2 hits) ', 'c-danger']], W, 't4'),
    window.row([T('   '), p('a-29'), m('   sysprompt-extract     '), [' covered (1 hit) ', 'c-warn']], W, 't5'),
    window.row([T('   '), p('a-31'), m('   training-data leak    '), m('not exercised · skip')], W, 't6'),
    window.row([T('   '), p('a-32'), m('   model-self-replication '), m('not exercised · skip')], W, 't7'),
    window.blankRow(W, 'b4'),
    window.logLine('flow','15:18:42',[m(' '), a('/use verify F-0012'),
      m('  to confirm the $-loss path · '), a('/use patch F-0012'),
      m(' to draft the staged role-tagged-user fix')], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · prompt-armor · RED FLAG">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'prompt-armor', cost: '$0.34' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'prompt-armor · 6 hits · 1 RED FLAG', findings: 38,
        promptModule: 'prompt-armor',
        keybinds: [['j/k','row'],['enter','open'],['/use verify','confirm'],['/use patch','draft']],
      })}
    </window.TermFrame>
  );
}
window.PromptArmorRedFlagView = PromptArmorRedFlagView;
