// theme picker · light · dark · high-contrast · solarized

function ThemePickerView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function swatch(focused, name, bg, fg, accent, sev, blurb) {
    const nCell = (name + ' '.repeat(22)).slice(0, 18);
    const sw = [
      ['  ', null],
      [' ', null],
      [' ' + bg + ' ', 'c-muted'],
      [' ', null],
      [' ' + fg + ' ', 'c-primary'],
      [' ', null],
      [' ' + accent + ' ', 'c-accent'],
      [' ', null],
      [' ' + sev + ' ', 'c-danger'],
    ];
    if (focused) {
      const text = ' ' + nCell + '  ' + bg + '  ' + fg + '  ' + accent + '  ' + sev + '   ' + blurb;
      return <span className="row" key={name}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([
      ['    ', null],
      [nCell, 'c-primary'],
      ...sw,
      [' ' + blurb, 'c-muted'],
    ], W, name);
  }

  const lines = [
    window.logLine('in','16:08:01',[m(' /setg theme ')], W, 'l1'),
    window.row([T('  '), m('current '), p('charcoal'),
      m('  ·  '), m('reads system pref '), p('--from-os'),
      m('  ·  '), m('per-tty override '), p('TERM_PROGRAM=iterm sets '), p('charcoal-iterm')], W, 'h0'),
    window.blankRow(W, 'b1'),
    window.sectionHeader('THEMES · 8 built-in', W, 's1'),
    swatch(true,  'charcoal',         '#0b0d10', '#cfd6e0', '#7fb8ff', '#e25c5c', 'default · low-glare on cooler displays'),
    swatch(false, 'paperwhite',       '#f6f4ef', '#1e2026', '#1a4fb2', '#a02020', 'light · printable · review-friendly'),
    swatch(false, 'high-contrast',    '#000000', '#ffffff', '#00ffff', '#ff5050', 'WCAG AAA · all roles ≥ 7:1'),
    swatch(false, 'solarized-dark',   '#002b36', '#93a1a1', '#268bd2', '#dc322f', 'classic · for the loyalists'),
    swatch(false, 'solarized-light',  '#fdf6e3', '#073642', '#268bd2', '#dc322f', 'paired with above for handoff'),
    swatch(false, 'amber',            '#1a0f00', '#ffb454', '#ffe680', '#ff7a3d', 'phosphor · evening operator mode'),
    swatch(false, 'gruvbox',          '#1d2021', '#ebdbb2', '#83a598', '#fb4934', 'warm earth · long-session friendly'),
    swatch(false, 'tokyo-night',      '#1a1b26', '#a9b1d6', '#7aa2f7', '#f7768e', 'familiar to vscode users'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('PREVIEW · charcoal · sample console', W, 's2'),
    window.row([T('   '), m('14:32:14 '), [' ● ', 'c-accent'], m(' /scan · plan confirmed')], W, 'pr1'),
    window.row([T('   '), m('14:32:14 '), [' ⏵ ', 'c-primary'], m(' sast:scan · tasks '),
      a('semgrep, secrets'),  m(' · triage on')], W, 'pr2'),
    window.row([T('   '), m('14:33:42 '), [' ◆ ', 'c-accent'],
      m(' two CRITICALs share a sink — '), a('F-0001'), m(' · '), a('F-0002')], W, 'pr3'),
    window.row([T('   '), m('14:33:42 '), [' ▸ ', 'c-warn'],
      [' F-0012 ', 'c-accent'], m(' · '), [' CRITICAL ', 'c-sev-critical'],
      m(' · '), p('refund-bot.ts:127')], W, 'pr4'),
    window.row([T('   '), m('15:46:01 '), [' ✗ ', 'c-danger'],
      [' HARD STOP ', 'c-danger'],  m(' · run budget reached')], W, 'pr5'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('ACCESSIBILITY · A11y guarantees per theme', W, 's3'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('contrast'),
      m('         all themes ≥ AA on text · '), p('high-contrast'),
      m(' is AAA on every role')], W, 'a1'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('color-blind safe'),
      m(' severity also encoded as '), p('CRIT/HIGH/MED/LOW'),
      m(' label · never color-only')], W, 'a2'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('motion'),
      m('             only progress bars + spinners move · '),
      a('/setg motion off'), m(' freezes them')], W, 'a3'),
    window.row([T('   '), [' ✓ ', 'c-success'], m('  '), p('font-size'),
      m('         '), a('/setg ui.font-size 14'),  m(' · scales the whole TUI')], W, 'a4'),
    window.row([T('   '), [' · ', 'c-subtle'], m('  '), p('reader-mode'),
      m('       '), a('/setg ui.reader on'),  m(' · linearizes tables for screen readers')], W, 'a5'),
    window.blankRow(W, 'b4'),
    window.sectionHeader('CUSTOM', W, 's4'),
    window.row([T('   '), m('   '), a('/setg theme.from-file ./theme.toml'),
      m('   8-role theme · same shape as built-ins')], W, 'cu1'),
    window.row([T('   '), m('   '), a('/show theme --print > my.toml'),
      m('         export the active theme as a starting point')], W, 'cu2'),
    window.row([T('   '), m('   '), a('/setg theme charcoal --override accent=#ff7a3d'),
      m('  one-role override')], W, 'cu3'),
    window.blankRow(W, 'b5'),
    window.logLine('flow','16:08:14',[m(' '), a('j/k'), m(' theme · '),
      a('enter'), m(' apply (live) · '),
      a('p'), m(' print sample · '),
      a('Esc'), m(' close')], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · /setg theme · 8 built-in">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'theme', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'theme · 8 built-in · current charcoal', findings: 38,
        promptModule: 'theme',
        keybinds: [['j/k','theme'],['enter','apply'],['p','print sample'],['Esc','close']],
      })}
    </window.TermFrame>
  );
}
window.ThemePickerView = ThemePickerView;
