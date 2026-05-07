// Randori view — PASTA threat model with ATT&CK + KEV intel overlay.
// Stages run sequentially; the operator sees the table fill in.

function RandoriView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const w = (t) => [t, 'c-warn'];
  const d = (t) => [t, 'c-danger'];
  const T = (t) => [t, null];

  function stage(num, name, status, summary, color) {
    return [
      [' ', null],
      [`  ${num}  `, 'c-subtle'],
      [(name + ' '.repeat(28)).slice(0, 26), 'c-accent'],
      [(status + ' '.repeat(16)).slice(0, 14), color],
      [summary, 'c-primary'],
    ];
  }

  function attack(tid, name, kev, where) {
    return [
      [' ', null],
      [(tid + ' '.repeat(10)).slice(0, 9), 'c-accent'],
      [(name + ' '.repeat(50)).slice(0, 42), 'c-primary'],
      [kev ? '★ KEV ' : '      ', kev ? 'c-danger' : 'c-subtle'],
      [where, 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('in', '14:36:00', [m(' /use '), a('randori')], W, 'l1'),
    window.logLine('in', '14:36:08', [m(' /run '), a('build --methodology PASTA --intel attack,kev')], W, 'l2'),
    window.logLine('run', '14:36:08', [m(' randori · 7-stage PASTA · pulling ATT&CK v15 + CISA KEV (cached 2h ago)')], W, 'l3'),
    window.blankRow(W, 'b1'),

    window.sectionHeader('PASTA · 7 stages', W, 'sec-pasta'),
    window.row(stage('I', 'objectives & scope', 'done', 'pulled from threat-model.json#v3', 'c-success'), W, 's1'),
    window.row(stage('II', 'technical scope',    'done', '6 stores, 9 trust-bounds, 14 flows', 'c-success'), W, 's2'),
    window.row(stage('III','application decompose','done','5 entrypoints · 4 services · 2 agent runtimes', 'c-success'), W, 's3'),
    window.row(stage('IV', 'threat analysis',     'done', '23 threats from ATT&CK enterprise', 'c-success'), W, 's4'),
    window.row(stage('V',  'vuln & weakness',     'done', 'mapped 8 sast findings to threats', 'c-success'), W, 's5'),
    window.row(stage('VI', 'attack modeling',     'done', '4 chains · longest 5 hops · scored', 'c-success'), W, 's6'),
    window.row(stage('VII','risk & impact',       'done', 'top chain → wire fraud · $1.2M ARR', 'c-success'), W, 's7'),
    window.blankRow(W, 'b2'),

    window.sectionHeader('TOP ATT&CK CHAIN · prompt-injection → wire fraud', W, 'sec-chain'),
    window.row(attack('T1190',  'Exploit Public-Facing App',           false, '/api/reviews · review.body taint source'), W, 'tt1'),
    window.row(attack('T1059',  'Command & Scripting Interpreter',     true,  'concierge agent splices into system prompt'), W, 'tt2'),
    window.row(attack('T1078',  'Valid Accounts',                      true,  'agent calls lookup_order with elevated svc-account'), W, 'tt3'),
    window.row(attack('T1565',  'Data Manipulation',                   false, 'agent flips refund_status via tool-call'), W, 'tt4'),
    window.row(attack('T1657',  'Financial Theft',                     false, 'refund settled to attacker-supplied account'), W, 'tt5'),
    window.blankRow(W, 'b3'),

    window.sectionHeader('KEV CALLOUTS · 2 actively-exploited', W, 'sec-kev'),
    window.row([T('   '), [' ★ ', 'c-danger'], a('CVE-2024-3094'), m('  xz-utils backdoor · transitive in '), p('debian:trixie'), m(' base layer')], W, 'k1'),
    window.row([T('   '), [' ★ ', 'c-danger'], a('CVE-2024-21887'), m(' Ivanti Connect Secure · only relevant if VPN bastion shares vlan')], W, 'k2'),
    window.blankRow(W, 'b4'),

    window.logLine('agent', '14:36:42', [
      [' the prompt-injection chain has both ', 'c-primary'],
      ['public-facing entry', 'c-warn'],
      [' and ', 'c-primary'],
      ['valid-account abuse', 'c-warn'],
      [' — score 9.1.', 'c-primary'],
    ], W, 'a1'),
    window.logLine('flow', '14:36:42', [m(' draft model written to '), p('.kuzushi/randori/v1.json'), m(' · diff with '), a('/randori diff')], W, 'a1b'),
  ];

  return (
    <window.TermFrame title="kuzushi · randori · PASTA + ATT&CK + KEV">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'randori', cost: '$0.31' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'randori (done) · top chain 9.1 · 2 KEV', findings: 8,
        promptModule: 'randori',
        keybinds: [
          ['/randori', 'diff | apply'], ['/show', 'chain top'],
          ['/use', 'sast'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.RandoriView = RandoriView;
