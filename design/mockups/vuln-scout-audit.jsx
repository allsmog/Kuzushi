// /use vuln-scout · audit ledger run

function VulnScoutAuditView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function row(idx, ts, actor, op, target, verdict) {
    const vMap = { ok:'c-success', warn:'c-warn', fail:'c-danger', info:'c-muted' };
    return [
      [' ', null],
      [(' ' + idx + ' ').slice(0, 6), 'c-subtle'],
      [(ts + ' '.repeat(20)).slice(0, 18), 'c-muted'],
      [(actor + ' '.repeat(14)).slice(0, 12), 'c-accent'],
      [(op + ' '.repeat(20)).slice(0, 18), 'c-primary'],
      [(target + ' '.repeat(40)).slice(0, 36), 'c-muted'],
      [verdict.label, vMap[verdict.kind]],
    ];
  }

  const lines = [
    window.logLine('in','15:28:01',[m(' /use vuln-scout '), a('--audit --since 24h')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('window  '), p('2026-05-05 15:28 → 2026-05-06 15:28'),
      m('   entries '), p('1842'),  m('   actors '), p('8'),
      m('   refusals '), p('14'),  m('   approvals '), p('22')], W, 'h0'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('LEDGER · last 14 · most recent first', W, 's1'),
    window.row([
      [' ', null], [('  #' + ' '.repeat(6)).slice(0, 6), 'c-label'],
      [('time' + ' '.repeat(18)).slice(0, 18), 'c-label'],
      [('actor' + ' '.repeat(12)).slice(0, 12), 'c-label'],
      [('op' + ' '.repeat(18)).slice(0, 18), 'c-label'],
      [('target' + ' '.repeat(36)).slice(0, 36), 'c-label'],
      ['verdict', 'c-label'],
    ], W, 'h'),
    window.row([[' ', null], ['─'.repeat(W - 2), 'c-subtle']], W, 'rule'),
    window.row(row(1842, '15:22:08 today', 'patcher',  'fs:write',           'apps/web/agents/concierge.ts',     {kind:'ok',   label:'applied  '}), W, 'r1'),
    window.row(row(1841, '15:22:02 today', 'verifier', 'sandbox:run',        'PoC F-0002 · rerun',                 {kind:'ok',   label:'fixed    '}), W, 'r2'),
    window.row(row(1840, '15:22:01 today', 'patcher',  'fs:write (test)',     'apps/web/agents/concierge.test.ts', {kind:'ok',   label:'applied  '}), W, 'r3'),
    window.row(row(1839, '15:18:42 today', 'attacker', 'kb:fetch',            'a-04 + a-08 + a-21',                 {kind:'info', label:'logged   '}), W, 'r4'),
    window.row(row(1838, '15:18:38 today', 'attacker', 'fs:read',             'concierge.ts:80..160',                {kind:'info', label:'logged   '}), W, 'r5'),
    window.row(row(1837, '15:14:38 today', 'attacker', 'sandbox:run',         'curl x-ray manifest',                  {kind:'info', label:'logged   '}), W, 'r6'),
    window.row(row(1836, '15:12:14 today', 'planner',  'tm:write',             '.kuzushi/threat-model.json (v3)',     {kind:'ok',   label:'applied  '}), W, 'r7'),
    window.row(row(1835, '15:10:22 today', 'planner',  'workspace:multi-init', '~/work/acme-monorepo',                 {kind:'ok',   label:'applied  '}), W, 'r8'),
    window.row(row(1834, '15:08:01 today', 'operator', 'findings:filter',      '--severity critical --module codeql',  {kind:'info', label:'logged   '}), W, 'r9'),
    window.row(row(1833, '15:06:38 today', 'planner',  'allowlist:deny',       '169.254.169.254',                      {kind:'ok',   label:'applied  '}), W, 'r10'),
    window.row(row(1832, '15:04:01 today', 'attacker', 'sandbox:run',          'curl metadata.google.internal',         {kind:'fail', label:'refused  '}), W, 'r11'),
    window.row(row(1831, '14:58:02 today', 'operator', 'load:gh',              'gh:acme/checkout#PR412',                {kind:'ok',   label:'applied  '}), W, 'r12'),
    window.row(row(1830, '14:56:18 today', 'planner',  'kb:pull',              'cisa-kev · nvd · attck',                {kind:'ok',   label:'applied  '}), W, 'r13'),
    window.row(row(1829, '14:54:09 today', 'operator', 'doctor',               '5 fail · 4 warn · 18 ok',                {kind:'warn', label:'flagged  '}), W, 'r14'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('AUDIT INVARIANTS', W, 's2'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('append-only'),
      m('         · 1842 lines · 0 holes · sha-chained on rotate')], W, 'i1'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('actor-tagged'),
      m('       · 100% have model + role + run + actor binding')], W, 'i2'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('redaction'),
      m('           · secret-scan upstream · 0 secret-shaped strings in log')], W, 'i3'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  '), p('clock skew'),
      m('          · 1 entry within 200ms of host clock jump (boot)')], W, 'i4'),
    window.blankRow(W, 'b4'),
    window.logLine('flow','15:28:01',[m(' '), a('--export jsonl > audit.jsonl'),
      m('  ·  '), a('--filter actor=attacker'),
      m('  ·  '), a('--since "now -7d"'),
      m('  ·  '), a('/use vendor-assessment')], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · vuln-scout · audit · 24h">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'vuln-scout', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'vuln-scout · audit · 1842 · 22 ok · 14 refusal', findings: 38,
        promptModule: 'vuln-scout',
        keybinds: [['j/k','row'],['enter','expand'],['--export','jsonl'],['--filter','grep']],
      })}
    </window.TermFrame>
  );
}
window.VulnScoutAuditView = VulnScoutAuditView;
