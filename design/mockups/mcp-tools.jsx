// mcp-tools · /mcp list · external tool servers attached

function McpToolsView() {
  const W = window.W120;
  const m = (t) => [t, 'c-muted'];
  const p = (t) => [t, 'c-primary'];
  const a = (t) => [t, 'c-accent'];
  const T = (t) => [t, null];

  function srvRow(focused, name, kind, ep, tools, calls, state, stateCls) {
    if (focused) {
      const text = ' ' + (name + ' '.repeat(18)).slice(0,18)
        + ' ' + (kind + ' '.repeat(8)).slice(0,8)
        + ' ' + (ep + ' '.repeat(34)).slice(0,34)
        + ' ' + (tools + ' '.repeat(7)).slice(0,7)
        + ' ' + (calls + ' '.repeat(11)).slice(0,11)
        + state;
      return <span className="row" key={name}><span className="c-accent">{'  ▌'}</span><span className="c-sel">{text}</span></span>;
    }
    return window.row([T('   '),
      [(name + ' '.repeat(18)).slice(0,18), 'c-primary'],
      [(kind + ' '.repeat(8)).slice(0,8), 'c-subtle'],
      [(ep + ' '.repeat(34)).slice(0,34), 'c-muted'],
      [(tools + ' '.repeat(7)).slice(0,7), 'c-accent'],
      [(calls + ' '.repeat(11)).slice(0,11), 'c-muted'],
      [' ' + state + ' ', stateCls],
    ], W, name);
  }

  const lines = [
    window.logLine('in','17:22:01',[m(' /mcp list ')], W, 'l1'),
    window.row([T('  '), m('5 servers '),
      m(' · negotiated tools '), p('appear under /tools'), m(' · '),
      m('every call goes through '), p('policy gate'), m(' · '),
      m('logs in '), p('~/.kuzushi/mcp.log')], W, 'h0'),
    window.blankRow(W, 'b1'),
    window.row([T('   '),
      [' SERVER             ', 'c-subtle'], [' KIND     ', 'c-subtle'],
      [' ENDPOINT                          ', 'c-subtle'],
      [' TOOLS  ', 'c-subtle'], [' CALLS (24h)', 'c-subtle'], [' STATE', 'c-subtle']], W, 'hd'),
    window.ruleRow(W, 'r0'),
    srvRow(true,  'gh-mcp',         'stdio',  '~/.local/bin/gh-mcp',                  '7',  '124',       'CONNECTED',  'c-success'),
    srvRow(false, 'jira-mcp',       'http',   'https://mcp.acme.io/jira',             '4',  '38',        'CONNECTED',  'c-success'),
    srvRow(false, 'datadog-mcp',    'http',   'https://mcp.acme.io/datadog',          '6',  '19',        'CONNECTED',  'c-success'),
    srvRow(false, 'vault-mcp',      'unix',   '/var/run/vault.sock',                  '2',  '0',         'CONNECTED',  'c-success'),
    srvRow(false, 'zendesk-mcp',    'http',   'https://mcp.acme.io/zendesk',          '—',  '—',         'AUTH-FAIL',  'c-danger'),
    window.blankRow(W, 'b2'),
    window.sectionHeader('TOOLS · gh-mcp · attached this session', W, 's1'),
    window.row([T('   '), [' ✓ ', 'c-success'], p(' gh.search_code        '), m('grep across repo · safe · cached')], W, 't1'),
    window.row([T('   '), [' ✓ ', 'c-success'], p(' gh.read_file          '), m('any path in attached repo')], W, 't2'),
    window.row([T('   '), [' ✓ ', 'c-success'], p(' gh.list_prs           '), m('open PRs · status + checks')], W, 't3'),
    window.row([T('   '), [' ✓ ', 'c-success'], p(' gh.read_pr            '), m('PR metadata + diff')], W, 't4'),
    window.row([T('   '), [' ⚠ ', 'c-warn'],    p(' gh.create_pr          '), m('write · '), [' requires confirm ', 'c-warn']], W, 't5'),
    window.row([T('   '), [' ⚠ ', 'c-warn'],    p(' gh.write_file         '), m('write · '), [' requires confirm ', 'c-warn']], W, 't6'),
    window.row([T('   '), [' ✗ ', 'c-danger'],  p(' gh.delete_repo        '), m('write · '), [' DENIED by policy ', 'c-danger']], W, 't7'),
    window.blankRow(W, 'b3'),
    window.sectionHeader('LAST CALL · gh.list_prs · 17:21:48', W, 's2'),
    window.row([T('   '), m('   '), p('args  '), a('{state:"open", limit:25}')], W, 'lc1'),
    window.row([T('   '), m('   '), p('took  '), a('842ms'), m('   · cached for '), a('15m')], W, 'lc2'),
    window.row([T('   '), m('   '), p('result'), a('25 PRs'), m('   · '), [' 200 OK ', 'c-success']], W, 'lc3'),
    window.blankRow(W, 'b4'),
    window.logLine('flow','17:22:14',[m(' '), a('j/k'), m(' server · '),
      a('enter'), m(' tools · '),
      a('a'), m(' add · '),
      a('r'), m(' reconnect · '),
      a('p'), m(' policy · '),
      a('Esc'), m(' close')], W, 'l3'),
  ];

  return (
    <window.TermFrame title="kuzushi · /mcp list · 5 servers · 19 tools">
      {window.statusStrip({ target: '~/work/acme-checkout', ctx: 'fresh', module: 'mcp', cost: '$0.00' })}
      {window.ruleRow(W, 'r1')}
      {window.blankRow(W, 'b1')}
      {lines}
      {window.blankRow(W, 'b-end')}
      {window.footer({
        stage: 'mcp · 5 servers · 19 tools attached · 1 auth-fail',
        findings: 0,
        promptModule: 'mcp',
        keybinds: [['j/k','server'],['enter','tools'],['a','add'],['r','reconnect'],['p','policy']],
      })}
    </window.TermFrame>
  );
}
window.McpToolsView = McpToolsView;
