// /share gen · signed-url generation

function ShareGenView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  const lines = [
    window.logLine('in','15:50:01',[m(' /share gen '), a('--bundle bundle-2026-05-06-1536')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('SCOPE · who can see this', W, 's1'),
    window.row([T('   '), m('audience '), p('triage'),
      m('  ·  '), m('viewers '), p('jen.t@acme'), m(', '), p('avi.k@acme'), m(', '), p('on-call rotation')], W, 'sc1'),
    window.row([T('   '), m('mode     '), p('viewer-only'),
      m(' · cannot rerun · cannot fork · cannot export · '),
      [' read + comment ', 'c-success']], W, 'sc2'),
    window.row([T('   '), m('expiry   '), p('7 days'),
      m(' · 2026-05-13 15:50 UTC · '), [' auto-revoke ', 'c-warn']], W, 'sc3'),
    window.row([T('   '), m('domain   '), p('@acme'),
      m(' enforced via SSO · external addresses refused at preview')], W, 'sc4'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('SIGNED URL', W, 's2'),
    window.row([T('   '), p('https://share.kuzushi.dev/v/'),
      [' a83b412e-…-c91f7d ', 'c-accent']], W, 'u1'),
    window.row([T('   '), m('         '), p('?sig=ZmFrZSBzaWcgZm9yIG1vY2suLi4&exp=1747403400&aud=triage')], W, 'u1b'),
    window.row([T('   '), m('integrity'), p(' sha256:a83b412e…  ·  '),
      m('signed-by '), p('avi.k@acme'),
      m('  ·  '), m('ttl '), p('7d')], W, 'u2'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('PRIVACY · what the viewer actually sees', W, 's3'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('findings'),
      m('       38 entries · raw secrets star-masked · file paths kept')], W, 'pv1'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('runs'),
      m('           3 curated · sysprompts redacted to fingerprints')], W, 'pv2'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('threat-model v3'),
      m(' rendered md only · raw json withheld')], W, 'pv3'),
    window.row([T('   '), [' ✗ ', 'c-danger'], m('  '), p('source tree'),
      m('     not included · only line snippets in findings')], W, 'pv4'),
    window.row([T('   '), [' ✗ ', 'c-danger'], m('  '), p('audit log'),
      m('       not included · entry-count visible only')], W, 'pv5'),
    window.row([T('   '), [' ✗ ', 'c-danger'], m('  '), p('budgets · costs'),
      m(' not included · operator-only')], W, 'pv6'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('REVOKE', W, 's4'),
    window.row([T('   '), m('   '), a('/share list'),
      m('             show all live shares for this workspace')], W, 'rv1'),
    window.row([T('   '), m('   '), a('/share revoke a83b412e'),
      m('   immediate · invalidates JWT and CDN cache')], W, 'rv2'),
    window.row([T('   '), m('   '), a('/share extend a83b412e --ttl 14d'),
      m('  push expiry · audit log gets a row')], W, 'rv3'),
    window.blankRow(W, 'b5'),
    window.logLine('flow','15:50:14',[m(' '), a('y'), m(' copy url to clipboard · '),
      a('e'), m(' email viewers (subj prefilled) · '),
      a('q'), m(' /share gen --slack-thread T01ABC/C2DE/123 · '),
      a('n'), m(' cancel & don\'t generate')], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · /share gen · triage bundle">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'share', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'share · gen · viewer-only · 7d ttl', findings: 38,
        promptModule: 'share',
        keybinds: [['y','copy'],['e','email'],['q','slack'],['n','cancel']],
      })}
    </window.TermFrame>
  );
}
window.ShareGenView = ShareGenView;
