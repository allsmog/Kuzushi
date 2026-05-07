// kuzushi doctor — preflight (config, state, scanners, bridge, models).

function DoctorView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];

  function check(state, label, blurb) {
    const g = state === 'ok' ? [' ✓ ', 'c-success']
            : state === 'warn' ? [' ! ', 'c-warn']
            : state === 'fail' ? [' ✗ ', 'c-danger']
            : [' · ', 'c-subtle'];
    return [
      ['  ', null], g, ['  ', null],
      [(label + ' '.repeat(34)).slice(0, 32), state === 'fail' ? 'c-warn' : 'c-primary'],
      [blurb, 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('in','14:55:00', [m(' kuzushi doctor --target .')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('CONFIG · ~/.kuzushi/v2/config.toml', W, 's1'),
    window.row(check('ok',   'global config',          '12 keys · last edited 2d ago'), W, 'c1'),
    window.row(check('ok',   'project override',       '.kuzushi/v2/config.toml · 3 keys'), W, 'c2'),
    window.row(check('ok',   'effective model',        'openai:gpt-4.1 (env wins over project)'), W, 'c3'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('STATE · .kuzushi/v2/', W, 's2'),
    window.row(check('ok',   'findings.sqlite3 openable','38 findings · 4 verified · 2 patched'), W, 'st1'),
    window.row(check('ok',   'attachments.json',       '10 attachments · 8 parsed'), W, 'st2'),
    window.row(check('ok',   'artifact-kb.sqlite3',    '92 chunks · last index 14:14'), W, 'st3'),
    window.row(check('warn', 'context-snapshot.json',  'stale (3h) · run /context build to refresh'), W, 'st4'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('SUBPROCESSES', W, 's3'),
    window.row(check('ok',   'semgrep',                '$PATH · semgrep 1.79.0'), W, 'sp1'),
    window.row(check('fail', 'codeql',                 'NOT FOUND · install or pass {"binary":"…"}'), W, 'sp2'),
    window.row(check('ok',   'nmap',                   '$PATH · nmap 7.94'), W, 'sp3'),
    window.row(check('ok',   'curl',                   '$PATH · curl 8.4.0'), W, 'sp4'),
    window.row(check('ok',   'docker (sandbox)',       'docker 25.0.3 · daemon up'), W, 'sp5'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('AGENT BRIDGE · pi-agent-core', W, 's4'),
    window.row(check('ok',   'KUZUSHI_AGENT_BRIDGE',   '/usr/local/bin/pi-agent-bridge'), W, 'b1b'),
    window.row(check('ok',   'bridge handshake',       '37ms · pi-agent-core 0.18.2 · pi-ai 0.4.1'), W, 'b2b'),
    window.row(check('ok',   'model channel · openai', 'gpt-4.1 reachable · 184ms'), W, 'b3b'),
    window.row(check('warn', 'model channel · anthropic','reachable · key expires in 4d'), W, 'b4b'),
    window.row(check('fail', 'model channel · google', 'GOOGLE_API_KEY missing'), W, 'b5b'),
    window.blankRow(W, 'b5'),
    window.sectionHeader('PLUGINS', W, 's5'),
    window.row(check('ok',   'KUZUSHI_SHINSA_PLUGIN',  '~/plugins/shinsa · v0.6.2'), W, 'pl1'),
    window.row(check('fail', 'KUZUSHI_VULN_SCOUT_PLUGIN','unset · vuln-scout:audit will refuse'), W, 'pl2'),
    window.row(check('fail', 'KUZUSHI_TOB_SKILLS_DIR', 'unset · tob:* will refuse'), W, 'pl3'),
    window.row(check('fail', 'KUZUSHI_PROMPT_ARMOR_PLUGIN','unset · prompt-armor:* will refuse'), W, 'pl4'),
    window.blankRow(W, 'b6'),
    window.logLine('agent','14:55:01', [
      [' ', null], ['7 ok · 2 warn · 5 fail', 'c-warn'],
      m('  ·  startup will succeed · runtime tools requiring '),
      ['google', 'c-warn'], m(', '), ['vuln-scout', 'c-warn'], m(', '), ['tob', 'c-warn'], m(', '), ['prompt-armor', 'c-warn'],
      m(' will refuse explicitly (no fallback model)'),
    ], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · doctor · preflight">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'stale (3h)', module: 'doctor', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'doctor · 7 ok · 2 warn · 5 fail', findings: 38,
        keybinds: [['/auth','login'],['/context','build'],['/config','init'],['j/k','row']],
      })}
    </window.TermFrame>
  );
}

window.DoctorView = DoctorView;
