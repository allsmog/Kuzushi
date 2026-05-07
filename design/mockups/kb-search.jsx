// kb-search · /kb search · cross-source results

function KbSearchView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function hit(focused, src, srcCls, id, title, score, when) {
    if (focused) {
      const text = ' ' + src + '  ' + id + '  ' + title + '   ' + score + '  ' + when;
      return <span className="row" key={id}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([T('   '),
      [' ' + (src + '   ').slice(0,8) + ' ', srcCls],
      ['  ', null],
      [(id + ' '.repeat(20)).slice(0,20), 'c-accent'],
      [(title + ' '.repeat(54)).slice(0,54), 'c-primary'],
      [(score + ' '.repeat(7)).slice(0,7), 'c-success'],
      [when, 'c-subtle'],
    ], W, id);
  }

  const lines = [
    window.logLine('in','17:48:01',[m(' /kb search "ssrf java spring webclient" ')], W, 'l1'),
    window.row([T('  '), m('searched '), p('5 sources'), m(' · '),
      a('142ms'), m(' · '), p('14 hits'),
      m(' across CVE feed · ToB blog · OWASP · semgrep rules · internal findings ledger')], W, 'h0'),
    window.blankRow(W, 'b1'),
    window.row([T('   '),
      [' SRC      ', 'c-subtle'], [' ID                  ', 'c-subtle'],
      [' TITLE                                                ', 'c-subtle'],
      [' SCORE  ', 'c-subtle'], [' WHEN', 'c-subtle']], W, 'hd'),
    window.ruleRow(W, 'r0'),
    hit(true,  'CVE',     'c-danger',  'CVE-2024-44331',     'Spring WebClient SSRF via redirect chain',           '0.91',  '14 days ago'),
    hit(false, 'CVE',     'c-danger',  'CVE-2023-20862',     'Spring Cloud Function SSRF (URL parser)',           '0.84',  '7 mo ago'),
    hit(false, 'rule',    'c-accent',  'semgrep:ssrf-java',  'spring webclient build() with user-controlled URL', '0.79',  'updated 3d ago'),
    hit(false, 'ledger',  'c-primary', 'F-0019',             'F-0019 SSRF · acme-checkout · refund-bot.ts',       '0.74',  'verified 2d ago'),
    hit(false, 'ToB',     'c-accent',  'blog:ssrf-2024',     'Why SSRF won\'t die · 2024 retrospective',           '0.71',  '4 mo ago'),
    hit(false, 'OWASP',   'c-accent',  'A10:2021',           'OWASP A10 SSRF · prevention cheatsheet',            '0.68',  'cheatsheet'),
    hit(false, 'rule',    'c-accent',  'semgrep:ssrf-redir', 'follow-redirects with user host (java)',            '0.65',  'updated 11d ago'),
    hit(false, 'ledger',  'c-primary', 'F-0007',             'F-0007 SSRF (CLOSED · false-positive)',             '0.61',  '21d ago'),
    hit(false, 'CVE',     'c-danger',  'CVE-2022-22965',     'Spring4Shell · adjacent class · SSRF chain',        '0.58',  '2y ago'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('PREVIEW · CVE-2024-44331', W, 's1'),
    window.row([T('   '), m('  '), p('summary  '), m('Redirect-following WebClient permits internal-host SSRF when')], W, 'pv1'),
    window.row([T('   '), m('  '), m('         '), m('  '),                  m('a redirect target lacks explicit scheme allowlisting.')], W, 'pv2'),
    window.row([T('   '), m('  '), p('versions '), m('spring-webflux '), a('< 6.1.4'), m(' · '), p('cvss '), [' 8.6 HIGH ', 'c-sev-high']], W, 'pv3'),
    window.row([T('   '), m('  '), p('use      '), m('try '), a('/run ndiff --cve CVE-2024-44331'), m(' to look for variants in your tree')], W, 'pv4'),
    window.row([T('   '), m('  '), p('nearby   '), m('your '), a('F-0019'), m(' likely shares the sink (ledger match · '), a('0.74'), m(')')], W, 'pv5'),
    window.blankRow(W, 'b3'),
    window.logLine('flow','17:48:14',[m(' '), a('j/k'), m(' hit · '),
      a('enter'), m(' open · '),
      a('h'), m(' hunt variants · '),
      a('s'), m(' refine · '),
      a('Esc'), m(' close')], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · /kb search · 14 hits · 5 sources">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'kb', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'kb search · 14 hits · top score 0.91 · CVE-2024-44331',
        findings: 0,
        promptModule: 'kb',
        keybinds: [['j/k','hit'],['enter','open'],['h','hunt variants'],['s','refine']],
      })}
    </window.TermFrame>
  );
}
window.KbSearchView = KbSearchView;
