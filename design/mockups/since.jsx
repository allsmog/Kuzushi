// /since v1.0.0 — diff-scoped findings.

function SinceView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function f(focused, alias, sev, when, name, where) {
    const sMap = { critical: 'c-sev-critical', high: 'c-sev-high', medium: 'c-sev-medium', low: 'c-sev-low' };
    const aCell = (alias + ' '.repeat(8)).slice(0, 7);
    const sCell = (sev.toUpperCase() + ' '.repeat(10)).slice(0, 9);
    const wCell = (when + ' '.repeat(8)).slice(0, 6);
    if (focused) {
      const text = ' ' + aCell + sCell + wCell + (name + ' '.repeat(60)).slice(0, 50) + ' ' + where + ' ';
      return <span className="row" key={alias}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return [
      ['    ', null],
      [aCell, 'c-accent'],
      [sCell, sMap[sev]],
      [wCell, 'c-muted'],
      [(name + ' '.repeat(60)).slice(0, 50), 'c-primary'],
      [where, 'c-muted'],
    ];
  }
  const wrap = (v, k) => Array.isArray(v) ? window.row(v, W, k) : v;

  const lines = [
    window.logLine('in','15:11:00',[m(' /since '), a('v1.0.0..HEAD')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('range  '), p('v1.0.0..HEAD'), m('  ·  '), p('612'), m(' commits  ·  '), p('1842'),
      m(' files touched  ·  '), p('+44k −12k'), m(' lines')], W, 'h1'),
    window.row([T('  '), m('scope  '), p('apps/, libs/, jobs/, infra/'), m('  ·  ignoring '), p('docs/, scripts/')], W, 'h2'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('NEW FINDINGS · 7 introduced since v1.0.0', W, 's1'),
    wrap(f(false,'F-0002','critical','12m','prompt-injection sink — model reads body',     'apps/web/agents/concierge.ts:88 (since v1.0.0+241)'), 'a'),
    wrap(f(true ,'F-0012','critical','11m','prompt-injection in refund-bot',                'apps/web/agents/refund-bot.ts:127 (introduced @v1.2.0)'), 'b'),
    wrap(f(false,'F-0013','high',    '11m','second-order injection · order.notes',          'apps/web/agents/concierge.ts:241 (since v1.0.0+512)'), 'c'),
    wrap(f(false,'F-0014','high',    '8m', 'shell exec from cron payload (regression)',     'jobs/worker.py:213 (introduced @v1.1.4)'), 'd'),
    wrap(f(false,'F-0015','high',    '8m', 'jwt secret leaked in admin subdomain config',   'infra/admin/values.yaml:14 (introduced @v1.2.1)'), 'e'),
    wrap(f(false,'F-0016','medium',  '6m', 'open redirect on /login?next=',                 'apps/web/server.ts:78 (since v1.0.0+312)'), 'f'),
    wrap(f(false,'F-0017','medium',  '6m', 'unbounded regex on /search',                    'apps/api/search.rs:31 (introduced @v1.2.0)'), 'g'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('CARRIED FORWARD · 4 still open from before v1.0.0', W, 's2'),
    wrap(f(false,'F-0001','critical','6h','sql injection via order_id concatenation',        'apps/api/orders.rs:142 (since v0.9)'), 'h'),
    wrap(f(false,'F-0009','low',    '1d', 'cors allows null origin',                         'apps/api/cors.rs:12 (since v0.7)'), 'i'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('FIXED IN RANGE · 2 closed since v1.0.0', W, 's3'),
    window.row([T('   '), m(' '), [' ✓ ', 'c-success'], m(' '), p('F-0007'), m('   csrf token not bound to session'), m('  ·  patched in '), p('v1.2.0')], W, 'fx1'),
    window.row([T('   '), m(' '), [' ✓ ', 'c-success'], m(' '), p('F-0003'), m('   jwt verify with alg=none accepted'), m('  ·  patched in '), p('v1.2.1')], W, 'fx2'),
    window.blankRow(W, 'b5'),
    window.logLine('agent','15:11:01',[
      m(' '), [' regression alert ', 'c-danger'],
      m('  ·  '), p('F-0014'), m(' looks like '), p('F-0011'), m(' from v0.9 — same author, similar patch was reverted in '),
      p('jobs/worker.py'), m('. Run '), a('/use ndiff'), m(' to confirm.'),
    ], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /since v1.0.0..HEAD">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: '—', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: '/since · 7 new · 4 carried · 2 fixed', findings: 38,
        keybinds: [['j/k','row'],['enter','open'],['/use ndiff','variant'],['/use patch','staged']],
      })}
    </window.TermFrame>
  );
}
window.SinceView = SinceView;
