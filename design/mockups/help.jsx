// Help view — `/help` grouped help. The catalog operator sees when they
// type `?` or `/help`. Sectioned like the README's command table.

function HelpView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function cmdRow(cmd, blurb) {
    return [
      [' ', null],
      [(cmd + ' '.repeat(48)).slice(0, 44), 'c-accent'],
      [blurb, 'c-primary'],
    ];
  }

  function sec(name, blurb) {
    return window.row([
      [' ', null],
      [`── ${name} `, 'c-label'],
      [`${blurb} `, 'c-muted'],
      ['─'.repeat(Math.max(0, W - 1 - 4 - name.length - 1 - blurb.length - 1)), 'c-subtle'],
    ], W, name);
  }

  const lines = [
    window.logLine('in',  '14:00:08', [m(' /help')], W, 'l1'),
    window.blankRow(W, 'b1'),

    sec('NAVIGATE', 'browse modules and tools'),
    window.row(cmdRow('/help, ?',                         'show this help'), W, 'n1'),
    window.row(cmdRow('/modules · /tools',                 'list visible native modules / tools'), W, 'n2'),
    window.row(cmdRow('/use <module>',                     'focus a module · prompt becomes kuzushi (mod)>'), W, 'n3'),
    window.row(cmdRow('/back',                             'pop the focused module'), W, 'n4'),
    window.blankRow(W, 'b2'),

    sec('RUN', 'dispatch tools and scans'),
    window.row(cmdRow('/run <tool> [json] · run . [json]', 'execute a registered tool with typed input'), W, 'r1'),
    window.row(cmdRow('/scan [target]',                    'native sast umbrella scan'), W, 'r2'),
    window.row(cmdRow('/ask <question>, ?text',            'explicit agent route — never silent'), W, 'r3'),
    window.row(cmdRow('/options [tool] · show missing',    'inspect typed options · see what\'s required'), W, 'r4'),
    window.row(cmdRow('/set <key> <value> · setg <k> <v>', 'session / global option overrides'), W, 'r5'),
    window.blankRow(W, 'b3'),

    sec('TASKS', 'control the sast umbrella'),
    window.row(cmdRow('/tasks',                            'list current task selection'), W, 't1'),
    window.row(cmdRow('/task block <id> · /task allow <id>','disable / enable a single task'), W, 't2'),
    window.row(cmdRow('/task mode auto|manual|toggle',     'how the umbrella picks tasks'), W, 't3'),
    window.row(cmdRow('/task reset',                       'restore default task set'), W, 't4'),
    window.blankRow(W, 'b4'),

    sec('CONTEXT & KB', 'workspace + attachments'),
    window.row(cmdRow('/context · /context build',         'view or rebuild the snapshot'), W, 'c1'),
    window.row(cmdRow('/context status · regen <slice>',   'check freshness · rebuild a slice'), W, 'c2'),
    window.row(cmdRow('/kb [module]',                      'browse local KB attachments'), W, 'c3'),
    window.row(cmdRow('attach <path-or-url> · detach <id>', 'add / remove attachments'), W, 'c4'),
    window.row(cmdRow('reparse <id>',                      're-extract content from an attachment'), W, 'c5'),
    window.blankRow(W, 'b5'),

    sec('FINDINGS', 'browse / open / triage'),
    window.row(cmdRow('/findings',                          'load persisted findings'), W, 'f1'),
    window.row(cmdRow('/open <alias-or-fingerprint>',       'open a finding by alias e.g. F-0001'), W, 'f2'),
    window.row(cmdRow('/show aliases [prefix]',             'list deterministic aliases'), W, 'f3'),
    window.row(cmdRow('/show runs · /replay <runId>',       'inspect / step a run'), W, 'f4'),
    window.row(cmdRow('/since <git-ref>',                   'diff-scoped findings since a ref'), W, 'f5'),
    window.blankRow(W, 'b6'),

    sec('THREATS', 'model + diff + ask'),
    window.row(cmdRow('/threats [dfd|stride|stories|scope|summary|1..5]','switch threat-model views'), W, 'th1'),
    window.row(cmdRow('/threats regen · /threats ask <q>',   'patch · ask a model question'), W, 'th2'),
    window.blankRow(W, 'b7'),

    sec('SESSION', 'auth, model, history'),
    window.row(cmdRow('/auth · /auth login <provider>',     'show creds status · log in'), W, 'sess1'),
    window.row(cmdRow('/provider · /backend · /model [c]',  'inspect / pick model + provider'), W, 'sess2'),
    window.row(cmdRow('/cost · /config',                    'spend so far · effective config'), W, 'sess3'),
    window.row(cmdRow('/history · /clear · /load <spec>',   'transcript utilities'), W, 'sess4'),
    window.row(cmdRow('/pause · /resume [runId]',           'control long-running scans'), W, 'sess5'),
    window.row(cmdRow('/quit, exit, /exit',                 'leave the shell'), W, 'sess6'),
    window.blankRow(W, 'b8'),

    window.logLine('log', '14:00:08', [m(' tip: '), a('Tab'), m(' completes commands · '), a('Ctrl+R'), m(' searches history · '), a('?<text>'), m(' is always agent-chat (never silent dispatch)')], W, 'l-end'),
  ];

  return (
    <window.TermFrame title="kuzushi · /help">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: '—', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'help', findings: 0,
        keybinds: [
          ['?<text>', 'agent chat'], ['Tab', 'complete'],
          ['Ctrl+R', 'search history'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.HelpView = HelpView;
