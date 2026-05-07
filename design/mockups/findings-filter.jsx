// /findings — filter pivot view, severity + status + assignee.

function FindingsFilterView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function row(focused, id, sev, status, who, age, name, where) {
    const sevMap = { critical:'c-sev-critical', high:'c-sev-high', medium:'c-sev-medium', low:'c-sev-low' };
    const stMap  = { open:'c-warn', verified:'c-success', fixed:'c-success', dup:'c-muted', wontfix:'c-subtle', triaging:'c-warn' };
    const idCell = (id + ' '.repeat(10)).slice(0, 8);
    const sevCell = (sev.toUpperCase() + ' '.repeat(10)).slice(0, 9);
    const stCell = (status + ' '.repeat(12)).slice(0, 10);
    const whoCell = (who + ' '.repeat(10)).slice(0, 8);
    const ageCell = (age + ' '.repeat(8)).slice(0, 6);
    const nCell = (name + ' '.repeat(60)).slice(0, 44);
    const wCell = where;
    if (focused) {
      const text = ' ' + idCell + sevCell + stCell + whoCell + ageCell + nCell + wCell;
      return <span className="row" key={id}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([
      ['    ', null],
      [idCell, 'c-accent'],
      [sevCell, sevMap[sev]],
      [stCell, stMap[status]],
      [whoCell, 'c-muted'],
      [ageCell, 'c-muted'],
      [nCell, 'c-primary'],
      [wCell, 'c-muted'],
    ], W, id);
  }

  function chip(label, on) {
    return [
      [' ', null],
      [' ' + label + ' ', on ? 'c-sel' : 'c-muted'],
      [' ', null],
    ];
  }
  const heads = window.row([
    ['    ', null],
    [('id' + ' '.repeat(8)).slice(0, 8), 'c-label'],
    [('sev' + ' '.repeat(9)).slice(0, 9), 'c-label'],
    [('status' + ' '.repeat(10)).slice(0, 10), 'c-label'],
    [('who' + ' '.repeat(8)).slice(0, 8), 'c-label'],
    [('age' + ' '.repeat(6)).slice(0, 6), 'c-label'],
    [('name' + ' '.repeat(44)).slice(0, 44), 'c-label'],
    ['where', 'c-label'],
  ], W, 'h');

  const filters = window.row([
    [' ', null],
    ['filter ', 'c-muted'],
    ...chip('CRITICAL', true), ...chip('HIGH', true), ...chip('medium', false), ...chip('low', false),
    [' · ', 'c-subtle'],
    ...chip('open', true), ...chip('triaging', true), ...chip('verified', true), ...chip('fixed', false), ...chip('wontfix', false),
    [' · ', 'c-subtle'],
    ...chip('@me', false), ...chip('any', true),
  ], W, 'flt');

  const lines = [
    window.logLine('in','14:28:01',[m(' /findings '), a('--severity high+ --status open,triaging,verified')], W, 'l1'),
    window.blankRow(W, 'b1'),
    filters,
    window.blankRow(W, 'b2'),
    window.row([T('  '), m('match '), p('11'), m(' / '), p('38'), m(' · '), m('sort '), p('severity desc, age asc')], W, 'h0'),
    window.blankRow(W, 'b3'),
    heads,
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'rule'),
    row(false, 'F-0001', 'critical', 'open',     'jen.t', '2m',  'sql injection via order_id concatenation',     'apps/api/orders.rs:142'),
    row(true,  'F-0002', 'critical', 'triaging', 'jen.t', '2m',  'prompt-injection sink (concierge)',            'apps/web/agents/concierge.ts:88'),
    row(false, 'F-0012', 'critical', 'open',     '—',     '6m',  'prompt-injection (refund-bot dollar exfil)',   'apps/web/agents/refund-bot.ts:127'),
    row(false, 'F-0003', 'high',     'verified', 'avi.k', '14m', 'jwt verify with alg=none accepted',            'apps/api/auth/jwt.rs:54'),
    row(false, 'F-0004', 'high',     'open',     '—',     '14m', 'shell exec from cron payload',                 'jobs/worker.py:213'),
    row(false, 'F-0005', 'high',     'open',     '—',     '14m', 'path traversal in /assets/<file>',             'apps/web/server.ts:301'),
    row(false, 'F-0019', 'high',     'triaging', 'avi.k', '1h',  'taint: review.body → exec sink',                'apps/web/agents/concierge.ts:142'),
    row(false, 'F-0023', 'high',     'open',     '—',     '1h',  'IDOR on /api/order/<other-tenant-id>',          'apps/api/orders.rs:88'),
    row(false, 'F-0027', 'high',     'open',     '—',     '2h',  'cross-lang taint py→ts via redis blob',         'jobs/worker.py:184'),
    row(false, 'F-0031', 'high',     'verified', 'jen.t', '2h',  'oauth state param not bound to session',        'apps/web/oauth.ts:61'),
    row(false, 'F-0034', 'high',     'open',     '—',     '3h',  'k8s deploy runs as root, capDrop missing',      'infra/k8s/api.yaml:14'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('BULK ACTIONS', W, 's2'),
    window.row([T('   '), [' a ', 'c-accent'], m('  assign '), p('@me'), m(' to selection · '),
      [' s ', 'c-accent'], m('  set status · '),
      [' x ', 'c-accent'], m('  export '), p('jsonl | sarif | csv'), m(' · '),
      [' . ', 'c-accent'], m('  /use verify')], W, 'b'),
    window.blankRow(W, 'b5'),
    window.logLine('flow','14:28:01',[m(' '), a('/findings --severity ! --since 24h'), m(' · '),
      a('--unassigned'), m(' · '), a('--cwe 89'), m(' · '), a('--module agentic-sast')], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /findings · filter">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'findings', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'findings · 11 of 38 match', findings: 38,
        promptModule: 'findings',
        keybinds: [['j/k','row'],['a','assign'],['s','status'],['x','export'],['enter','open']],
      })}
    </window.TermFrame>
  );
}
window.FindingsFilterView = FindingsFilterView;
