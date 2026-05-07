// /show options carlini --after-tune — module-scoped config detail.

function ModuleOptionsView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function opt(name, type, val, scope, desc) {
    const sMap = { default: 'c-muted', user: 'c-accent', project: 'c-accent', env: 'c-warn', run: 'c-success' };
    return [
      [' ', null],
      [(name + ' '.repeat(28)).slice(0, 24), 'c-primary'],
      [(type + ' '.repeat(10)).slice(0, 8), 'c-muted'],
      [(val + ' '.repeat(20)).slice(0, 18), 'c-primary'],
      [(' ' + scope + ' '.repeat(10)).slice(0, 10), sMap[scope] || 'c-muted'],
      [desc, 'c-muted'],
    ];
  }

  const heads = window.row([
    [' ', null],
    [('option' + ' '.repeat(24)).slice(0, 24), 'c-label'],
    [('type' + ' '.repeat(8)).slice(0, 8), 'c-label'],
    [('value' + ' '.repeat(18)).slice(0, 18), 'c-label'],
    [(' scope' + ' '.repeat(10)).slice(0, 10), 'c-label'],
    ['description', 'c-label'],
  ], W, 'h');

  const lines = [
    window.logLine('in','14:14:08',[m(' /use '), a('carlini')], W, 'l1'),
    window.logLine('in','14:14:11',[m(' /show options')], W, 'l2'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('module '), p('carlini'), m('  '),
      m('describes '), p('Carlini-style adversarial threat hunt'), m('  '),
      m('actor '), p('attacker'), m('  '),
      m('budget '), p('$2.50 / run')], W, 'h1'),
    window.blankRow(W, 'b2'),
    heads,
    window.row([[' ', null], ['─'.repeat(W - 2), 'c-subtle']], W, 'r'),
    window.row(opt('TARGET',         'path',   '~/work/acme-checkout', 'project', 'workspace root'), W, 'o1'),
    window.row(opt('THREAT_MODEL',   'path',   'auto',                 'default', 'auto = read .kuzushi/threat-model.json'), W, 'o2'),
    window.row(opt('HORIZON',        'int',    '3',                    'default', 'planner depth · raise for harder targets'), W, 'o3'),
    window.row(opt('FRAMES',         'int',    '64',                   'user',    'max agent steps before pause'), W, 'o4'),
    window.row(opt('BUDGET',         'usd',    '2.50',                 'user',    'cost cap · soft pause at 80%'), W, 'o5'),
    window.row(opt('PERSIST',        'bool',   'true',                 'default', 'write findings to .kuzushi/v2/findings.sqlite3'), W, 'o6'),
    window.row(opt('SAFE_MODE',      'bool',   'true',                 'default', 'no destructive verbs · no host-fs writes'), W, 'o7'),
    window.row(opt('NETWORK',        'enum',   'stub',                 'project', 'stub | allowlist | open  · stub = mocked targets'), W, 'o8'),
    window.row(opt('SANDBOX',        'enum',   'firejail',             'env',     'firejail | docker | none'), W, 'o9'),
    window.row(opt('SEED',           'int',    '0',                    'default', '0 = nondeterministic; set for repro'), W, 'o10'),
    window.row(opt('PROMPT_TUNE',    'string', 'a-04 + a-08',          'run',     'tunes loaded by /tune'), W, 'o11'),
    window.row(opt('NOTES_DIR',      'path',   '.kuzushi/notes',       'default', 'agent scratchpad'), W, 'o12'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('OVERRIDES · 3', W, 's2'),
    window.row([T('   '), [' run ', 'c-success'], m('   '), p('PROMPT_TUNE'), m(' = '), p('a-04 + a-08'), m('  set by '), a('/tune load a-04')], W, 'ov1'),
    window.row([T('   '), [' env ', 'c-warn'],    m('   '), p('SANDBOX'), m(' = '), p('firejail'), m('     from '), p('KUZUSHI_SANDBOX')], W, 'ov2'),
    window.row([T('   '), [' user', 'c-accent'],  m('   '), p('FRAMES'), m(' = '), p('64'), m('             ~/.kuzushi/v2/options.toml')], W, 'ov3'),
    window.blankRow(W, 'b4'),
    window.logLine('flow','14:14:11',[m(' '), a('/set <opt> <val>'), m(' for run-scope · '), a('/setg'), m(' for global')], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · carlini · /show options">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'carlini', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'options · carlini · 12 keys · 3 overridden', findings: 38,
        promptModule: 'carlini',
        keybinds: [['/set','run-scope'],['/setg','global'],['/unsetg','clear'],['/run','dispatch']],
      })}
    </window.TermFrame>
  );
}
window.ModuleOptionsView = ModuleOptionsView;
