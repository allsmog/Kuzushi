// /tools — registered tool catalog with typed input shape.

function ToolsView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];

  function tool(focused, id, kind, blurb, schema) {
    const idCell = (id + ' '.repeat(36)).slice(0, 34);
    const kCell  = (kind + ' '.repeat(12)).slice(0, 10);
    const bCell  = (blurb + ' '.repeat(80)).slice(0, 36);
    const sCell  = schema;
    if (focused) {
      const text = ' ' + idCell + kCell + bCell + sCell + ' ';
      return <span className="row" key={id}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return [
      ['    ', null],
      [idCell, 'c-accent'],
      [kCell, 'c-muted'],
      [bCell, 'c-primary'],
      [sCell, 'c-muted'],
    ];
  }
  const wrap = (v, k) => Array.isArray(v) ? window.row(v, W, k) : v;

  const heads = window.row([
    ['    ', null],
    [('tool' + ' '.repeat(34)).slice(0, 34), 'c-label'],
    [('kind' + ' '.repeat(10)).slice(0, 10), 'c-label'],
    [('blurb' + ' '.repeat(36)).slice(0, 36), 'c-label'],
    ['typed input', 'c-label'],
  ], W, 'h');

  const lines = [
    window.logLine('in','15:01:30',[m(' /tools '), a('--module sast')], W, 'l1'),
    window.blankRow(W, 'b1'),
    heads,
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'rule'),
    wrap(tool(false,'context:build',           'native', 'index workspace into snapshot',           '{ paths?, since? }'), 'a'),
    wrap(tool(false,'recon:nmap',              'native', 'tcp/udp scan of host or network',         '{ host, ports?, udp? }'), 'b'),
    wrap(tool(false,'recon:subdomain',         'native', 'enumerate subdomains via passive sources','{ apex, sources? }'), 'c'),
    wrap(tool(false,'threat-model:build',      'native', 'STRIDE DFD over the snapshot',            '{ method?, scope? }'), 'd'),
    wrap(tool(false,'threat-model:apply',      'native', 'commit drafted patch to model.json',      '{ approve: true }'), 'e'),
    wrap(tool(true ,'sast:scan',               'native', 'umbrella · semgrep + secrets + agentic',  '{ paths?, tasks?, triage? }'), 'f'),
    wrap(tool(false,'semgrep:scan',            'native', 'pattern-based SAST',                      '{ rules?, paths? }'), 'g'),
    wrap(tool(false,'codeql:scan',             'native', 'CodeQL CLI scan',                         '{ db?, suite?, binary? }'), 'h'),
    wrap(tool(false,'secret-scan:scan',        'native', 'deterministic secret detector',           '{ paths?, allowlist? }'), 'i'),
    wrap(tool(false,'iac-scan:terraform',      'native', 'tf surface scan',                         '{ root, severity? }'), 'j'),
    wrap(tool(false,'iac-scan:k8s',            'native', 'manifest scan',                           '{ paths?, profile? }'), 'k'),
    wrap(tool(false,'dep-hygiene:check',       'native', 'lockfile + advisory check',               '{ ecosystems? }'), 'l'),
    wrap(tool(false,'agentic-sast:scan',       'native', 'LLM-driven dataflow + variant hunt',      '{ scope?, depth?, budget? }'), 'm'),
    wrap(tool(false,'carlini-threat-hunt:run', 'native', 'adversarial threat hunt',                 '{ h?, scope? }'), 'n'),
    wrap(tool(false,'taint-iris:hunt',         'native', 'taint-source → sink agent loop',          '{ src?, sink? }'), 'o'),
    wrap(tool(false,'variant:lift',            'native', 'lift CVE PoC to a hunt query',            '{ cve, lang? }'), 'p'),
    wrap(tool(false,'ndiff:hunt',              'native', 'diff two refs · variant-aware',           '{ before, after }'), 'q'),
    wrap(tool(false,'triage:run',              'native', 'classify raw hits into findings',         '{ input?, since? }'), 'r'),
    wrap(tool(false,'verify:run',              'native', 'reproduce + confirm',                     '{ id, rerun? }'), 's'),
    wrap(tool(false,'patch:run',               'native', 'suggest a fix patch',                     '{ id, staged? }'), 't'),
    wrap(tool(false,'findings:list',           'native', 'list/filter persisted findings',          '{ severity?, status?, query? }'), 'u'),
    wrap(tool(false,'shinsa:scan',             'plugin', 'compliance scan',                         '{ framework, controls? }'), 'v'),
    wrap(tool(false,'prompt-armor:scan',       'plugin', 'agent attack surface',                    '{ agent, matrix? }'), 'w'),
    wrap(tool(false,'tob:audit',               'plugin', 'audit skills',                            '{ skill, scope? }'), 'x'),
    window.blankRow(W, 'b2'),
    window.logLine('flow','15:01:30',[m(' '), a('/options sast:scan'), m(' for typed shape · '), a('/run sast:scan {…}'), m(' to invoke')], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /tools">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'sast', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: '/tools · 24 registered', findings: 38,
        keybinds: [['j/k','row'],['enter','/options'],['r','/run'],['/options','schema']],
      })}
    </window.TermFrame>
  );
}
window.ToolsView = ToolsView;
