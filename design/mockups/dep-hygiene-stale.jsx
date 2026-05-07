// dep-hygiene · upgrade plan + stale critical

function DepHygieneStaleView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function dep(focused, name, cur, want, sev, why) {
    const sevMap = { critical:'c-sev-critical', high:'c-sev-high', medium:'c-sev-medium', low:'c-sev-low', '·':'c-subtle' };
    const nCell  = (name + ' '.repeat(28)).slice(0, 26);
    const cCell  = (cur + ' '.repeat(14)).slice(0, 12);
    const wCell  = (want + ' '.repeat(14)).slice(0, 12);
    const sCell  = (sev.toUpperCase() + ' '.repeat(10)).slice(0, 9);
    if (focused) {
      const text = ' ' + nCell + cCell + wCell + sCell + why;
      return <span className="row" key={name}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([
      ['    ', null],
      [nCell, 'c-primary'],
      [cCell, 'c-muted'],
      [wCell, 'c-success'],
      [sCell, sevMap[sev]],
      [why, 'c-muted'],
    ], W, name);
  }

  const heads = window.row([
    ['    ', null],
    [('package' + ' '.repeat(26)).slice(0, 26), 'c-label'],
    [('current' + ' '.repeat(12)).slice(0, 12), 'c-label'],
    [('want' + ' '.repeat(12)).slice(0, 12), 'c-label'],
    [('sev' + ' '.repeat(9)).slice(0, 9), 'c-label'],
    ['why', 'c-label'],
  ], W, 'h');

  const lines = [
    window.logLine('in','15:42:01',[m(' /run dep-hygiene:check')], W, 'l1'),
    window.logLine('ok','15:42:18',[m(' '), p('482 deps'), m(' across '), p('cargo · npm · pip · go-mod'),
      m(' · '), p('41 stale'), m(' · '), p('5 with advisories'), m(' · '), p('2 critical')], W, 'l2'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('CRITICAL · upgrade asap', W, 's1'),
    heads,
    window.row([['    ', null], ['─'.repeat(W - 4), 'c-subtle']], W, 'r'),
    dep(true,  'postgres-rs (cargo)',   '0.7.21',     '0.7.24',     'critical', 'CVE-2026-2941 · auth bypass · 14d old'),
    dep(false, 'curl (transitive)',      '8.4.0',      '8.6.1',      'high',     'CVE-2026-2877 · CRLF inject · via reqwest'),
    dep(false, 'openssl-sys (cargo)',    '0.9.99',     '0.9.106',    'medium',   'CVE-2026-2710 · DoS only'),
    dep(false, 'lodash (npm)',           '4.17.20',    '4.17.21',    'low',       'prototype-pollution · old fix'),
    dep(false, 'requests (pip)',         '2.31.0',     '2.32.3',     'low',       'verify=false default in dev path'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('STALE · no advisory but 6+ months behind · 14 of 36', W, 's2'),
    dep(false, 'tokio (cargo)',          '1.36.0',     '1.42.0',     '·',         '6 months · 8 minor releases'),
    dep(false, 'react (npm)',            '18.2.0',     '18.3.1',     '·',         '8 months · patch only'),
    dep(false, 'serde (cargo)',          '1.0.197',    '1.0.214',    '·',         '4 months · low risk'),
    dep(false, 'tracing (cargo)',        '0.1.40',     '0.1.42',     '·',         '5 months'),
    dep(false, 'fastapi (pip)',          '0.110.0',    '0.114.0',    '·',         '7 months'),
    window.row([T('     '), m('… 9 more · '), a('/use dep-hygiene --stale-only'), m(' to drill')], W, 'mor'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('UPGRADE PLAN · F-0061 (postgres-rs)', W, 's3'),
    window.row([T('   '), m('shape       '), p('cargo update -p postgres-rs --precise 0.7.24')], W, 'u1'),
    window.row([T('   '), m('blast radius'), p('libs/payments + apps/api/auth · 8 files import')], W, 'u2'),
    window.row([T('   '), m('breakage    '), p('none expected'), m(' · upstream changelog: only auth path + 1 deprecated alias')], W, 'u3'),
    window.row([T('   '), m('test plan   '), p('cargo test --workspace + libs/payments::pam_tests')], W, 'u4'),
    window.row([T('   '), m('rollback    '), p('snapshot s-0044 (auto)'),
      m(' · '), a('/rollback s-0044'), m(' to revert')], W, 'u5'),
    window.row([T('   '), m('also update '), p('cargo.lock'), m(' · '), p('Cargo.toml')], W, 'u6'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('NDIFF LINK', W, 's4'),
    window.row([T('   '), [' ▸ ', 'c-warn'], m('  '), p('CVE-2026-2941'),
      m(' was fed to '), a('/use ndiff'), m(' earlier · 1 candidate at '), p('libs/auth/pam_native.rs:84')], W, 'n1'),
    window.row([T('   '), m('     '), m('upgrade alone '),
      [' does not ', 'c-warn'],
      m(' close the variant in your code · '),
      a('/use patch F-0041'), m(' to fix the local instance')], W, 'n2'),
    window.blankRow(W, 'b5'),
    window.logLine('flow','15:42:18',[m(' '), a('/use dep-hygiene --upgrade postgres-rs'),
      m(' · '), a('/use dep-hygiene --upgrade-all critical'),
      m(' · '), a('/use dep-hygiene --diff prev'), m(' to see how the tree changed')], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · dep-hygiene · 41 stale · 2 critical">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'dep-hygiene', cost: '$0.04' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'dep-hygiene · 482 deps · 2 critical · 41 stale', findings: 40,
        promptModule: 'dep-hygiene',
        keybinds: [['j/k','row'],['enter','open'],['/use dep-hygiene','upgrade'],['/use ndiff','hunt']],
      })}
    </window.TermFrame>
  );
}
window.DepHygieneStaleView = DepHygieneStaleView;
