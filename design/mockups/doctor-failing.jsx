// doctor · failing preflight

function DoctorFailingView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function chk(state, label, val, hint) {
    const map = { ok:[' ✓ ','c-success'], warn:[' ! ','c-warn'], fail:[' ✗ ','c-danger'], skip:[' · ','c-subtle'] };
    return [
      [' ', null], map[state], [' ', null],
      [(label + ' '.repeat(36)).slice(0, 30), 'c-primary'],
      [(val + ' '.repeat(34)).slice(0, 30), 'c-muted'],
      [hint || '', state === 'fail' ? 'c-danger' : state === 'warn' ? 'c-warn' : 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('in','14:54:01',[m(' doctor')], W, 'l1'),
    window.logLine('run','14:54:01',[m(' running 28 checks · 4 lanes · '), p('binary'), m(' · '),
      p('config'), m(' · '), p('models'), m(' · '), p('plugins')], W, 'l2'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('BINARY', W, 's1'),
    window.row(chk('ok',    'kuzushi version',          '0.18.2',                    ''), W, 'b1a'),
    window.row(chk('warn',  'channel update',           '0.19.0 available · 3d',     'see /update --dry-run'), W, 'b1b'),
    window.row(chk('ok',    'data dir writable',        '~/.kuzushi/v2',             ''), W, 'b1c'),
    window.row(chk('ok',    'workspace dir writable',   '.kuzushi/v2',                ''), W, 'b1d'),
    window.row(chk('warn',  'free disk',                '4.2 GB on /',               '< 5 GB · gc may fail'), W, 'b1e'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('CONFIG', W, 's2'),
    window.row(chk('ok',    'config schema',            'v6 · current',              ''), W, 'c1'),
    window.row(chk('ok',    'options.toml parse',       '12 keys · 3 overridden',    ''), W, 'c2'),
    window.row(chk('warn',  'env override surprises',   'KUZUSHI_TRIAGE_FLOOR=high', 'overrides project · acknowledge with /env-allow'), W, 'c3'),
    window.row(chk('ok',    'audit log writable',       '~/.kuzushi/v2/audit.log',   ''), W, 'c4'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('MODELS', W, 's3'),
    window.row(chk('ok',    'openai key',               'sk-…vQ8R · used 2m ago',   ''), W, 'm1'),
    window.row(chk('ok',    'anthropic key',            'sk-ant-…pZ12 · 14h ago',    ''), W, 'm2'),
    window.row(chk('fail',  'github token',             'expired 3d ago',            'run /auth login github · /load gh:* refused'), W, 'm3'),
    window.row(chk('skip',  'google key',               'not configured',            'optional'), W, 'm4'),
    window.row(chk('ok',    'local · ollama',           '@127.0.0.1:11434',          'qwen2.5-coder:32b reachable'), W, 'm5'),
    window.row(chk('fail',  'role: redteam binding',    '— · default attacker',      'rebind via /actor'), W, 'm6'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('PLUGINS · binaries · sandboxes', W, 's4'),
    window.row(chk('fail',  'codeql binary',            'not on PATH',               'brew install codeql · /run codeql:* refused'), W, 'p1'),
    window.row(chk('ok',    'semgrep binary',           '1.62.0',                    ''), W, 'p2'),
    window.row(chk('ok',    'firejail',                 '0.9.72',                    'sandbox:run will use this'), W, 'p3'),
    window.row(chk('skip',  'docker',                   'not installed',             'optional · alt sandbox'), W, 'p4'),
    window.row(chk('fail',  'tob skills dir',           'KUZUSHI_TOB_SKILLS_DIR unset','/run tob:* refused'), W, 'p5'),
    window.row(chk('fail',  'shinsa plugin',            'KUZUSHI_SHINSA_PLUGIN unset','/run shinsa:* refused'), W, 'p6'),
    window.row(chk('warn',  'prompt-armor plugin',      '~/plugins/prompt-armor v0.4','older than recommended (v0.6+)'), W, 'p7'),
    window.blankRow(W, 'b5'),
    window.sectionHeader('SUMMARY', W, 's5'),
    window.row([T('   '), m('checks   '), p('28'), m('   '), [' ✓ 18 ', 'c-success'], [' ! 4 ', 'c-warn'],
      [' ✗ 5 ', 'c-danger'], [' · 1 skip ', 'c-subtle']], W, 'sm1'),
    window.row([T('   '), m('blocking '), p('5'), m(' · github auth · redteam binding · codeql · tob · shinsa')], W, 'sm2'),
    window.row([T('   '), m('non-blocking '), p('4'), m(' · update available · disk · env override · prompt-armor version')], W, 'sm3'),
    window.blankRow(W, 'b6'),
    window.logLine('flow','14:54:09',[m(' '), a('doctor --fix'),
      m('  attempt automatic fix where safe · '), a('doctor --json'),
      m(' for ci')], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · doctor · 5 fail · 4 warn">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'doctor', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'doctor · 5 fail · 4 warn · 18 ok', findings: 38,
        promptModule: 'doctor',
        keybinds: [['--fix','auto'],['--json','ci'],['/auth login','remediate']],
      })}
    </window.TermFrame>
  );
}
window.DoctorFailingView = DoctorFailingView;
