// Error: no-plugin. Refusing tob:audit when KUZUSHI_TOB_SKILLS_DIR unset.

function ErrNoPluginView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  const lines = [
    window.logLine('in','13:55:31',[m(' /use '), a('tob')], W, 'l1'),
    window.logLine('in','13:55:38',[m(' /run tob:audit '), a('{"skill":"web-app-pentest"}')], W, 'l2'),
    window.logLine('err','13:55:38',[
      m(' '), [' tob:audit refused ', 'c-danger'], m(' · plugin not configured'),
    ], W, 'l3'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('REASON', W, 's1'),
    window.row([T('   '), m('plugin gate    '), p('KUZUSHI_TOB_SKILLS_DIR'), m('   '), [' ✗ unset ', 'c-danger']], W, 'r1'),
    window.row([T('   '), m('expected at    '), p('~/plugins/tob/skills/'), m('  ·  contents '), m('— ')], W, 'r2'),
    window.row([T('   '), m('module policy  '), m('refuse · '), p('tob/*'), m(' tools depend on operator-supplied skills')], W, 'r3'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('SIMILAR', W, 's2'),
    window.row([T('   '), [' ✗ ', 'c-danger'], m('  '), p('vuln-scout'), m('  KUZUSHI_VULN_SCOUT_PLUGIN unset')], W, 'sim1'),
    window.row([T('   '), [' ✗ ', 'c-danger'], m('  '), p('prompt-armor'), m('  KUZUSHI_PROMPT_ARMOR_PLUGIN unset')], W, 'sim2'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('shinsa'), m('       KUZUSHI_SHINSA_PLUGIN ok · ~/plugins/shinsa v0.6.2')], W, 'sim3'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('FIX', W, 's3'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  install ToB skills:  '), a('git clone github.com/trailofbits/audit-skills ~/plugins/tob'), m('  then')], W, 'f1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), a('export KUZUSHI_TOB_SKILLS_DIR=~/plugins/tob/skills'),
      m('   (or persist via '), a('~/.kuzushi/v2/env'), m(')')], W, 'f2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  re-run · '), a('/run tob:audit {"skill":"web-app-pentest"}')], W, 'f3'),
    window.blankRow(W, 'b4'),
    window.logLine('flow','13:55:38',[m(' '), a('doctor'), m(' enumerates every plugin gate · '), a('/modules'), m(' shows refusing modules')], W, 'l4'),
  ];

  return (
    <window.TermFrame title="kuzushi · tob · NO PLUGIN">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'tob', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'tob · refused · plugin missing', findings: 38,
        promptModule: 'tob',
        keybinds: [['doctor','preflight'],['/modules','status'],['/back','catalog']],
      })}
    </window.TermFrame>
  );
}
window.ErrNoPluginView = ErrNoPluginView;
