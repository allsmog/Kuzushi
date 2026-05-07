// /kb — local KB attachments. Reads from .kuzushi/v2/attachments.json.

function KbView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function att(focused, id, kind, source, parsed, chunks, used) {
    const kMap = { url: 'c-accent', file: 'c-primary', git: 'c-success', cve: 'c-warn', model: 'c-label' };
    const idCell = (id + ' '.repeat(8)).slice(0, 6);
    const kCell  = (kind + ' '.repeat(8)).slice(0, 6);
    const sCell  = (source + ' '.repeat(56)).slice(0, 56);
    const pCell  = parsed ? [' ✓ ', 'c-success'] : [' … ', 'c-warn'];
    const cCell  = (chunks + ' '.repeat(8)).slice(0, 8);
    const uCell  = (used + ' '.repeat(20)).slice(0, 18);
    if (focused) {
      const text = ' ' + idCell + kCell + sCell + (parsed ? ' ✓ ' : ' … ') + cCell + uCell + ' ';
      return <span className="row" key={id}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return [
      ['    ', null],
      [idCell, 'c-subtle'],
      [kCell, kMap[kind] || 'c-muted'],
      [sCell, 'c-primary'],
      pCell,
      [cCell, 'c-muted'],
      [uCell, 'c-muted'],
    ];
  }
  const wrap = (v, k) => Array.isArray(v) ? window.row(v, W, k) : v;

  const heads = window.row([
    ['    ', null],
    [('id' + ' '.repeat(6)).slice(0, 6), 'c-label'],
    [('kind' + ' '.repeat(6)).slice(0, 6), 'c-label'],
    [('source' + ' '.repeat(56)).slice(0, 56), 'c-label'],
    [' p ', 'c-label'],
    [('chunks' + ' '.repeat(8)).slice(0, 8), 'c-label'],
    ['used by', 'c-label'],
  ], W, 'h');

  const lines = [
    window.logLine('in','15:04:30',[m(' /kb')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.row([T('  '), m('store '), p('.kuzushi/v2/artifact-kb.sqlite3'), m('  ·  '), p('92'), m(' chunks  ·  last index '), p('14:14')], W, 'h1'),
    window.blankRow(W, 'b2'),
    heads,
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'rule'),
    wrap(att(false,'a-01','url',   'https://owasp.org/Top10/A03_2021-Injection',                'y',  '6',  'agentic-sast'), 'a'),
    wrap(att(false,'a-02','url',   'https://docs.oai.com/responses-api/best-practices',         'y', '11',  'prompt-armor'), 'b'),
    wrap(att(false,'a-03','file',  'docs/security-review-template.md',                          'y',  '4',  'shinsa, tob'), 'c'),
    wrap(att(true ,'a-04','cve',   'CVE-2024-1234 · curl strncpy heap overflow',                'y',  '8',  'variant, ndiff'), 'd'),
    wrap(att(false,'a-05','cve',   'CVE-2024-32896 · pixel kernel uaf',                         'y',  '6',  'variant'), 'e'),
    wrap(att(false,'a-06','file',  'reports/last-pentest-2025q1.pdf',                           'y', '14',  'threat-model'), 'f'),
    wrap(att(false,'a-07','git',   'github.com/acme/checkout@v1.0.0..HEAD',                      'y', '22',  'ndiff, agentic-sast'), 'g'),
    wrap(att(false,'a-08','model', 'system-card · openai gpt-4.1',                              'y',  '3',  'prompt-armor'), 'h'),
    wrap(att(false,'a-09','file',  'libs/payments/RFC-pci-2026.docx',                            'n',  '0',  '—'), 'i'),
    wrap(att(false,'a-10','url',   'https://attack.mitre.org/techniques/T1059/',                 'y',  '4',  'randori'), 'j'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('a-04 · CVE-2024-1234 · DETAIL', W, 's2'),
    window.row([T('   '), m('parsed       '), p('2026-05-03 09:11'), m('  ·  embeds '), p('text-embedding-3-small')], W, 'd1'),
    window.row([T('   '), m('chunks       '), p('8 · ~480 tok avg'), m('  ·  last cited '), p('14:31 by agentic-sast')], W, 'd2'),
    window.row([T('   '), m('cite count   '), p('14'), m(' across '), p('3'), m(' runs')], W, 'd3'),
    window.row([T('   '), m('next         '), a('/kb open a-04'), m('  ·  '), a('/kb reparse a-04'), m('  ·  '), a('/kb detach a-04')], W, 'd4'),
    window.blankRow(W, 'b4'),
    window.logLine('flow','15:04:30',[m(' '), a('attach <path-or-url>'), m(' to add  ·  '), a('reparse <id>'), m(' to re-extract  ·  '), a('detach <id>'), m(' to remove')], W, 'l2'),
  ];

  return (
    <window.TermFrame title="kuzushi · /kb">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: '—', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: '/kb · 10 attachments · 92 chunks', findings: 38,
        keybinds: [['j/k','row'],['enter','open'],['attach','add'],['reparse','re-extract']],
      })}
    </window.TermFrame>
  );
}
window.KbView = KbView;
