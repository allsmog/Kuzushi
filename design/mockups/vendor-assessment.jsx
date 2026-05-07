// Vendor-assessment view — assess a third-party vendor's security posture.
// Operator attaches a SOC2 / questionnaire / website, scope is set, model
// answers the questionnaire from the attached evidence.

function VendorAssessmentView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const w = (t) => [t, 'c-warn'];
  const T = (t) => [t, null];

  function attach(kind, name, size, source) {
    const c = kind === 'pdf' ? 'c-danger' : kind === 'url' ? 'c-accent' : 'c-warn';
    return [
      [' ', null],
      [`  [${kind}]   `, c],
      [(name + ' '.repeat(50)).slice(0, 46), 'c-primary'],
      [(size + ' '.repeat(10)).slice(0, 9), 'c-muted'],
      [source, 'c-muted'],
    ];
  }

  function q(num, prompt, verdict, evidence) {
    const c = verdict === 'YES' ? 'c-success' : verdict === 'NO' ? 'c-danger' : 'c-warn';
    return [
      [' ', null],
      [`  Q${String(num).padStart(2,'0')}  `, 'c-subtle'],
      [(prompt + ' '.repeat(70)).slice(0, 56), 'c-primary'],
      [(verdict + '   ').slice(0, 8), c],
      [evidence, 'c-muted'],
    ];
  }

  const lines = [
    window.logLine('in',  '15:42:01', [m(' /use '), a('vendor-assessment')], W, 'l1'),
    window.logLine('in',  '15:42:11', [m(' /run '), a('attach ./evidence/segment-pay-soc2.pdf')], W, 'l2'),
    window.logLine('in',  '15:42:14', [m(' /run '), a('attach https://segmentpay.com/security')], W, 'l3'),
    window.logLine('in',  '15:42:18', [m(' /run '), a('scope --tier critical --data PII,PCI')], W, 'l4'),
    window.logLine('run', '15:42:18', [m(' vendor-assessment · vendor '), a('SegmentPay'), m(' · tier '), w('critical'), m(' · '), p('48'), m(' questions')], W, 'l5'),
    window.blankRow(W, 'b1'),

    window.sectionHeader('ATTACHMENTS · 3', W, 'sec-att'),
    window.row(attach('pdf', 'segment-pay-soc2-2025-q3.pdf',         '4.2 MB', 'local · ./evidence/'), W, 'a1'),
    window.row(attach('url', 'segmentpay.com/security',              '—',      'fetched 14:55'), W, 'a2'),
    window.row(attach('csv', 'segment-pay-questionnaire-replies.csv', '38 KB',  'local · ./evidence/'), W, 'a3'),
    window.blankRow(W, 'b2'),

    window.sectionHeader('SCOPE', W, 'sec-sc'),
    window.row([T('   '), m('tier        '), w('critical'), m(' (handles cardholder data)')], W, 'sc1'),
    window.row([T('   '), m('data classes'), p(' PII, PCI-DSS')], W, 'sc2'),
    window.row([T('   '), m('integration '), p(' webhook + js sdk + iframe')], W, 'sc3'),
    window.row([T('   '), m('frameworks  '), p(' SOC 2 Type II, PCI DSS 4.0, ISO 27001')], W, 'sc4'),
    window.blankRow(W, 'b3'),

    window.sectionHeader('QUESTIONNAIRE · 48 · top 8 shown', W, 'sec-q'),
    window.row(q(1, 'SOC 2 Type II in last 12 months',                          'YES',     'soc2.pdf · sect 1.2 · auditor Schellman'), W, 'q1'),
    window.row(q(2, 'PCI DSS 4.0 attestation current',                          'YES',     'aoc-2025-09.pdf · valid through 09/26'), W, 'q2'),
    window.row(q(3, 'Encryption at rest (AES-256+) for all customer data',     'YES',     'soc2.pdf · CC6.7 control'), W, 'q3'),
    window.row(q(4, 'Sub-processor list public + change notice ≥ 30d',         'PARTIAL', 'list public · notice window 14d only'), W, 'q4'),
    window.row(q(5, 'Pen-test annual + remediation evidence',                   'YES',     'pentest-2025-04.pdf · all H closed'), W, 'q5'),
    window.row(q(6, 'Supports SSO / SCIM (SAML or OIDC)',                       'NO',      'website only mentions API keys'), W, 'q6'),
    window.row(q(7, 'IR plan tested in last 12 months',                         'PARTIAL', 'plan exists; tabletop in 2024-Q1'), W, 'q7'),
    window.row(q(8, 'Data residency · EU customers stay in EU',                 'NO',      'all data in us-east-1 per soc2 sect 4'), W, 'q8'),
    window.row([T('   '), m('   … 40 more · '), a('/show questionnaire all')], W, 'q-more'),
    window.blankRow(W, 'b4'),

    window.sectionHeader('VERDICT', W, 'sec-v'),
    window.row([T('   '), [' ! ', 'c-warn'], m(' '), p('CONDITIONAL'), m(' — 6 risks open · '), w('SSO/SCIM'), m(', '), w('EU residency'), m(' are blocking')], W, 'v1'),
    window.row([T('   '), m('   recommended controls: '), p('contractual SSO commitment'), m(', '), p('DPA addendum for EU'), m(', '), p('14d→30d sub-processor notice')], W, 'v2'),
    window.blankRow(W, 'b5'),

    window.logLine('agent', '15:42:54', [m(' two NO answers are dealbreakers for the '), w('critical'), m(' tier · escalate to legal before signature.')], W, 'l-end'),
    window.logLine('log',   '15:42:54', [m(' wrote '), p('.kuzushi/vendor-assessment/segmentpay-2026-05-06.json'), m(' · '), p('signed by avi.k')], W, 'l-end2'),
  ];

  return (
    <window.TermFrame title="kuzushi · vendor-assessment · SegmentPay · critical">
      {window.statusStrip({ target: 'vendor:SegmentPay', ctx: 'evidence (3)', module: 'vendor-assessment', cost: '$0.42' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'vendor-assessment · CONDITIONAL · 6 risks', findings: 6,
        promptModule: 'vendor-assessment',
        keybinds: [
          ['/show', 'questionnaire all'], ['/vendor', 'export | sign'],
          ['/attach', '<path|url>'], ['/back', 'catalog'],
        ],
      })}
    </window.TermFrame>
  );
}

window.VendorAssessmentView = VendorAssessmentView;
