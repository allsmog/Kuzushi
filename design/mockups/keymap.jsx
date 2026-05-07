// /help · keymap reference

function KeymapView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function k(keys, what) {
    const kCell = (keys + ' '.repeat(20)).slice(0, 18);
    return [
      [' ', null],
      [kCell, 'c-accent'],
      [' ', null],
      [what, 'c-muted'],
    ];
  }

  function head(name, blurb) {
    return window.row([
      [' ', null], [`── ${name} `, 'c-label'],
      [`${blurb} `, 'c-muted'],
      ['─'.repeat(Math.max(0, W - 1 - 4 - name.length - 1 - blurb.length - 1)), 'c-subtle'],
    ], W, name);
  }

  const lines = [
    window.logLine('in','16:00:01',[m(' /help'),  m(' or '), a('?')], W, 'l1'),
    window.blankRow(W, 'b1'),
    head('GLOBAL', 'work everywhere'),
    window.row(k('?',                    'this page'), W, 'g1'),
    window.row(k('Tab',                  'cycle focus · prompt → list → main → footer'), W, 'g2'),
    window.row(k('Ctrl-C  ·  Ctrl-D',    'quit (with confirm if dirty)'), W, 'g3'),
    window.row(k('Ctrl-L',               'clear console (keeps state · audit log untouched)'), W, 'g4'),
    window.row(k('Ctrl-P',               'command palette · all commands fuzzy-find'), W, 'g5'),
    window.row(k('Ctrl-R',               'recall last command · prefix-search history'), W, 'g6'),
    window.row(k('Esc',                  'cancel field / close overlay / interrupt streaming'), W, 'g7'),
    window.row(k(':number',              'jump to line in history (e.g. :142 in /tail)'), W, 'g8'),
    window.blankRow(W, 'b2'),
    head('NAVIGATION', 'list views · findings · runs · diffs'),
    window.row(k('j  ·  k',              'down  ·  up'), W, 'n1'),
    window.row(k('h  ·  l',              'collapse  ·  expand'), W, 'n2'),
    window.row(k('g  ·  G',              'top  ·  bottom'), W, 'n3'),
    window.row(k('Ctrl-D  ·  Ctrl-U',    'half-page down  ·  up'), W, 'n4'),
    window.row(k('enter',                'open / drill in'), W, 'n5'),
    window.row(k('o',                    'open as live trace (for runs / frames)'), W, 'n6'),
    window.row(k('y',                    'yank · copy id or path under cursor'), W, 'n7'),
    window.blankRow(W, 'b3'),
    head('DISPATCH', 'commands you reach for daily'),
    window.row(k('/scan',                'sast umbrella · semgrep + secrets + agentic'), W, 'd1'),
    window.row(k('/use <module>',       'enter a module · /use sast · /use ndiff cve-…'), W, 'd2'),
    window.row(k('/run <module>',       'one-shot a module without entering it'), W, 'd3'),
    window.row(k('/show <kind>',        '/show runs · /show options · /show findings · /show kb'), W, 'd4'),
    window.row(k('/set · /setg',        'session option · global default'), W, 'd5'),
    window.row(k('/use threat-model',   'plan or update v3'), W, 'd6'),
    window.row(k('/use patch <id>',     'draft a patch from a finding · staged · operator confirms'), W, 'd7'),
    window.row(k('/use verify <id>',    'sandbox-prove a finding · canary in · verdict out'), W, 'd8'),
    window.blankRow(W, 'b4'),
    head('LIFECYCLE', 'pause · resume · checkpoint · revert'),
    window.row(k('/pause',               'pause active run · checkpoint written · resumable'), W, 'lc1'),
    window.row(k('/resume r-…',         'resume from last frame · or specific frame with --from'), W, 'lc2'),
    window.row(k('/snapshot tag <name>','manual workspace snapshot · 30d retain'), W, 'lc3'),
    window.row(k('/rollback snap-…',    'restore · creates snap-now first · reversible'), W, 'lc4'),
    window.row(k('/budget',              'set or read run/operator/org caps'), W, 'lc5'),
    window.blankRow(W, 'b5'),
    head('VIEW · this screen', 'changes per-module · check the footer'),
    window.row(k('/?  ·  ?',             'show this'), W, 'v1'),
    window.row(k('/keys --module sast',  'just the keymap for sast'), W, 'v2'),
    window.row(k('/keys --print',        'render a printable cheat-sheet (md → /export)'), W, 'v3'),
    window.blankRow(W, 'b6'),
    window.row([T('   '), m('every screen\'s footer is the contract · if a key isn\'t in the footer, it doesn\'t do anything on that screen'),
    ], W, 'note'),
  ];

  return (
    <window.TermFrame title="kuzushi · /help · keymap">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'help', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'help · keymap', findings: 38,
        promptModule: 'help',
        keybinds: [['j/k','row'],['Esc','close'],['/keys --print','export']],
      })}
    </window.TermFrame>
  );
}
window.KeymapView = KeymapView;
