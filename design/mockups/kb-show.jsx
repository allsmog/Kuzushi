// /kb show · advisory detail

function KbShowView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  const lines = [
    window.logLine('in','15:48:01',[m(' /kb show '), a('CVE-2026-2941')], W, 'l1'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('CVE-2026-2941 · postgres · auth bypass under PAM', W, 's1'),
    window.row([T('   '), m('feed       '), p('cisa-kev'), m(', '), p('nvd'), m(', '), p('rustsec')], W, 'k1'),
    window.row([T('   '), m('cvss       '), p('9.1 / CRITICAL'),
      m('   added '), p('2026-05-02'),  m('   kev '), p('yes'),  m('   patched '), p('postgres 17.4')], W, 'k2'),
    window.row([T('   '), m('summary    '), p('PAM short-circuit on auth-err sets session anyway · login proceeds')], W, 'k3'),
    window.row([T('   '), m('refs       '), p('postgresql.org/docs/CVE-2026-2941'),  m('   '),
      p('rustsec.org/advisories/RUSTSEC-2026-0021')], W, 'k4'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('UPSTREAM PATCH SHAPE', W, 's2'),
    window.row([T('   '), [' h1 ', 'c-warn'], m('  '), p('src/backend/auth/pam.c'), m(' · short-circuit on PAM_AUTH_ERR'),
      m('   shape '), p('auth-err + state-mutated')], W, 'sh1'),
    window.row([T('   '), [' h2 ', 'c-warn'], m('  '), p('src/backend/auth/auth.c'), m(' · fallthrough on retry'),
      m('             shape '), p('retry-leak')], W, 'sh2'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('IMPACT · this workspace', W, 's3'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  '), p('libs/payments/src/auth.rs:84..118'),
      m(' · variant of '), p('h1'), m(' · '), p('shape match 0.91'),
      m('   ('), [' high ', 'c-sev-high'], m(')')], W, 'i1'),
    window.row([T('   '), [' ! ', 'c-warn'], m('  '), p('apps/api/sessions/issue.rs:201..240'),
      m(' · variant of '), p('h2'), m(' · '), p('shape match 0.74'),
      m(' ('), [' med ', 'c-sev-medium'], m(')')], W, 'i2'),
    window.row([T('   '), [' · ', 'c-subtle'], m('  '), p('lockfile'),
      m('  · '), p('postgres-rs 0.7.21'), m(' uses upstream <17.4 · '),
      p('upgrade to 0.7.24')], W, 'i3'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('ATT&CK', W, 's4'),
    window.row([T('   '), p('T1078'),     m('   valid accounts          '), m('relevant')], W, 'a1'),
    window.row([T('   '), p('T1556.006'), m(' modify auth process pam ')], W, 'a2'),
    window.row([T('   '), p('TA0001'),    m('   initial access            '), m('relevant')], W, 'a3'),
    window.blankRow(W, 'b5'),
    window.sectionHeader('SUGGESTED RUNS', W, 's5'),
    window.row([T('   '), [' 1 ', 'c-accent'], m('  '), a('/use ndiff CVE-2026-2941'),
      m('              hunt variants in this workspace')], W, 'r1'),
    window.row([T('   '), [' 2 ', 'c-accent'], m('  '), a('/use patch postgres-rs --pin 0.7.24'),
      m('     bump · staged-only')], W, 'r2'),
    window.row([T('   '), [' 3 ', 'c-accent'], m('  '), a('/use threat-model --add-risk CVE-2026-2941'),
      m('  surface in v3')], W, 'r3'),
    window.row([T('   '), [' 4 ', 'c-accent'], m('  '), a('/run dep-hygiene --upgrade-plan'),
      m('         broader sweep')], W, 'r4'),
  ];

  return (
    <window.TermFrame title="kuzushi · /kb show · CVE-2026-2941">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'kb', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'kb · CVE-2026-2941 · 2 likely variants · 1 dep', findings: 38,
        promptModule: 'kb',
        keybinds: [['/use ndiff','hunt'],['/use patch','bump'],['/findings','link']],
      })}
    </window.TermFrame>
  );
}
window.KbShowView = KbShowView;
