// /auth login anthropic — OAuth flow in progress.

function AuthOauthView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  const lines = [
    window.logLine('in','14:22:01',[m(' /auth login '), a('anthropic')], W, 'l1'),
    window.logLine('run','14:22:01',[m(' starting browser flow · listener on '), p('127.0.0.1:53892')], W, 'l2'),
    window.blankRow(W, 'b1'),
    window.row([T('   '), m('opening '), p('https://console.anthropic.com/oauth/authorize?…'), m(' in your browser')], W, 'r1'),
    window.row([T('   '), m('if it does not open, paste the URL above into a browser')], W, 'r2'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('WAITING FOR CALLBACK', W, 's1'),
    window.row([T('   '), [' … ', 'c-warn'], m('  '), p('14.7s'), m(' elapsed · timeout in '), p('45s')], W, 'w1'),
    window.row([T('   '), m('device code   '), p('NTRT-PVZQ'), m('  ·  show in browser if prompted')], W, 'w2'),
    window.row([T('   '), m('scopes        '), p('models:read, models:invoke, billing:read')], W, 'w3'),
    window.row([T('   '), m('store target  '), p('macOS keychain'), m(' · service '), p('kuzushi.anthropic')], W, 'w4'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('PARALLEL STATE', W, 's2'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('openai'), m('       sk-…vQ8R     last 2m ago')], W, 'p1'),
    window.row([T('   '), [' … ', 'c-warn'],    m('  '), p('anthropic'), m('    awaiting auth (this flow)')], W, 'p2'),
    window.row([T('   '), [' ✗ ', 'c-danger'],  m('  '), p('google'), m('       not configured')], W, 'p3'),
    window.row([T('   '), [' ! ', 'c-warn'],    m('  '), p('github'), m('       expired 3d ago')], W, 'p4'),
    window.blankRow(W, 'b4'),
    window.row([T('   '), [' i ', 'c-accent'], m('  press '), a('Ctrl+C'), m(' to cancel · '),
      a('/auth status'), m(' for state · '), a('/auth rotate <prov>'), m(' to re-auth without removing')], W, 'i1'),
    window.blankRow(W, 'b5'),
    window.logLine('flow','14:22:16',[m(' if you authenticated as a different account, '),
      a('/auth logout anthropic'), m(' first')], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · /auth login anthropic · in flight">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: '—', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: '/auth · oauth · waiting on callback · 14.7s', findings: 38,
        keybinds: [['Ctrl+C','cancel'],['/auth status','state'],['/auth logout','remove']],
      })}
    </window.TermFrame>
  );
}
window.AuthOauthView = AuthOauthView;
