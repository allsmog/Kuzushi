// network · /allowlist · denied egress + edit

function NetworkAllowlistView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function r(state, host, scope, hits, last) {
    const map = { allow:[' ✓ ','c-success'], deny:[' ✗ ','c-danger'], pending:[' … ','c-warn'] };
    return [
      [' ', null], map[state], [' ', null],
      [(host + ' '.repeat(40)).slice(0, 36), 'c-primary'],
      [(scope + ' '.repeat(14)).slice(0, 12), 'c-accent'],
      [(String(hits) + ' '.repeat(8)).slice(0, 6), 'c-muted'],
      [last, 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('in','15:06:01',[m(' /allowlist')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('mode '), p('allowlist'), m('  ·  '), m('default '), p('deny'),
      m('  ·  '), m('proxy '), p('—'), m('  ·  '), m('dns '), p('host')], W, 'h0'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('RULES · 12', W, 's1'),
    window.row(r('allow',   'refund.acme',                   'project', 41,  '14:32:18'), W, 'a1'),
    window.row(r('allow',   '*.acme-checkout-stg.com',       'project', 188, '14:33:01'), W, 'a2'),
    window.row(r('allow',   'api.openai.com',                'global',  612, '14:48:21'), W, 'a3'),
    window.row(r('allow',   'api.anthropic.com',             'global',  248, '14:33:42'), W, 'a4'),
    window.row(r('allow',   'github.com',                    'global',   18, '14:58:02'), W, 'a5'),
    window.row(r('allow',   'feed.cisa.dhs.gov',             'global',    2, '14:56:01'), W, 'a6'),
    window.row(r('allow',   'ollama@127.0.0.1:11434',        'global',  142, '15:01:18'), W, 'a7'),
    window.row(r('deny',    '*.evil.example',                'project',   0, 'never'),    W, 'a8'),
    window.row(r('deny',    'metadata.google.internal',      'global',    1, '14:21:08 (blocked)'), W, 'a9'),
    window.row(r('deny',    '169.254.169.254',               'global',    0, 'never'),    W, 'a10'),
    window.row(r('pending', 'pricing.refund.acme',           'run',       0, 'awaiting confirm dialog'), W, 'a11'),
    window.row(r('pending', 'webhook.demo.acme',             'run',       0, 'awaiting confirm dialog'), W, 'a12'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('RECENT BLOCKS · 24h · 6', W, 's2'),
    window.row([T('   '), m('14:21:08 '), [' deny ', 'c-danger'], m(' '), p('agent → metadata.google.internal'),  m('   reason '), p('cloud-imds class · always denied')], W, 'r1'),
    window.row([T('   '), m('13:52:14 '), [' deny ', 'c-danger'], m(' '), p('agent → 169.254.169.254'),           m('   reason '), p('imds class · always denied')], W, 'r2'),
    window.row([T('   '), m('11:18:42 '), [' deny ', 'c-danger'], m(' '), p('agent → discord.com'),                m('   reason '), p('not on allowlist')], W, 'r3'),
    window.row([T('   '), m('10:42:08 '), [' deny ', 'c-danger'], m(' '), p('agent → pastebin.com'),               m('   reason '), p('exfil class denylist')], W, 'r4'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('EDIT', W, 's3'),
    window.row([T('   '), [' a ', 'c-accent'], m('  /allowlist add '), p('<host>'), m('  ·  '),
      [' d ', 'c-accent'], m('  /allowlist deny '), p('<host>'),  m('  ·  '),
      [' x ', 'c-accent'], m('  /allowlist rm '), p('<host>')], W, 'e1'),
    window.row([T('   '), [' p ', 'c-accent'], m('  /allowlist proxy '), p('http://corp-proxy:3128'),
      m('  ·  '), [' e ', 'c-accent'], m('  /allowlist edit')], W, 'e2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /allowlist">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'allowlist', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'allowlist · 7 allow · 3 deny · 2 pending', findings: 38,
        promptModule: 'allowlist',
        keybinds: [['a','add'],['d','deny'],['x','rm'],['p','proxy'],['e','edit']],
      })}
    </window.TermFrame>
  );
}
window.NetworkAllowlistView = NetworkAllowlistView;
