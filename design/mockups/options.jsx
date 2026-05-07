// /options sast:scan — typed schema with required/missing markers.

function OptionsView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function opt(req, name, type, val, blurb) {
    const reqGlyph = req === 'req' ? [' ! ', 'c-warn']
                   : req === 'miss' ? [' ✗ ', 'c-danger']
                   : req === 'set' ? [' ✓ ', 'c-success']
                   : [' · ', 'c-subtle'];
    const nCell = (name + ' '.repeat(20)).slice(0, 20);
    const tCell = (type + ' '.repeat(20)).slice(0, 18);
    const vCell = ((val ?? '') + ' '.repeat(28)).slice(0, 26);
    return [
      ['  ', null], reqGlyph, ['  ', null],
      [nCell, 'c-accent'],
      [tCell, 'c-muted'],
      [vCell, val == null ? 'c-subtle' : 'c-primary'],
      [blurb, 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('in', '15:02:14', [m(' /options '), a('sast:scan'), m(' '), a('--missing')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('tool   '), p('sast:scan'), m('   ·   module '), p('sast'), m('   ·   typed input '), p('SastScanInput')], W, 'h1'),
    window.row([T('  '), m('schema '), p('apps/kuzushi/native/sast/scan.rs#46')], W, 'h2'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('OPTIONS', W, 'sec'),
    window.row(opt('set',  'paths',          '[String]',          '["apps/", "libs/"]',     'paths to scan; default workspace root'), W, 'o1'),
    window.row(opt('opt',  'tasks',          '[Task]',            null,                     'subset of {semgrep, secret-scan, agentic-sast}'), W, 'o2'),
    window.row(opt('set',  'triage',         'bool',              'true',                   'run triage post-scan'), W, 'o3'),
    window.row(opt('opt',  'severity_floor', 'Severity',          'medium',                 'drop hits below this severity from output'), W, 'o4'),
    window.row(opt('miss', 'scope',          'Scope',             null,                     'one of {workspace, since:<ref>, paths:<…>}'), W, 'o5'),
    window.row(opt('opt',  'language_hints', '[Lang]',            null,                     'force language detection'), W, 'o6'),
    window.row(opt('opt',  'sandbox',        'Sandbox',           'docker',                 'docker | none — sandbox child processes'), W, 'o7'),
    window.row(opt('opt',  'concurrency',    'u32',               '4',                      'task parallelism'), W, 'o8'),
    window.row(opt('opt',  'budget',         'Money?',            null,                     'optional cost cap; None ⇒ session budget'), W, 'o9'),
    window.row(opt('opt',  'timeout_s',      'u32',               '900',                    'hard ceiling'), W, 'o10'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('SOURCES (precedence: env > flag > project > global)', W, 'sec2'),
    window.row([T('   '), m('global  '), p('~/.kuzushi/v2/config.toml'), m('  ·  '), m('triage=true'), m(', '), m('concurrency=4')], W, 's1'),
    window.row([T('   '), m('project '), p('.kuzushi/v2/config.toml'), m('  ·  '), m('paths=["apps/","libs/"]')], W, 's2'),
    window.row([T('   '), m('env     '), p('KUZUSHI_SANDBOX=docker')], W, 's3'),
    window.row([T('   '), m('flag    '), p('--tasks semgrep,agentic-sast')], W, 's4'),
    window.blankRow(W, 'b4'),
    window.logLine('agent', '15:02:14', [
      m(' missing required: '), ['scope', 'c-danger'],
      m(' · set with '), a('/set scope workspace'), m(' or '), a('/run sast:scan {"scope":"workspace"}'),
    ], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /options sast:scan --missing">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'sast', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: '/options sast:scan · 1 missing', findings: 38,
        promptModule: 'sast',
        keybinds: [['/set','set value'],['e','edit json'],['Tab','complete keys'],['/run','dispatch']],
      })}
    </window.TermFrame>
  );
}
window.OptionsView = OptionsView;
