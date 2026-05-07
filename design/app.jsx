const { DesignCanvas, DCSection, DCArtboard } = window;

function App() {
  // 120 cols × ~12.5px font ≈ 1080px wide; height ~ rows × 16px line-height
  const W = 1100;

  // Helper that no-ops when a view isn't yet defined, so the canvas keeps
  // rendering even before every screen is wired in.
  const Slot = (name) => {
    const View = window[name];
    if (typeof View === 'function') return <View />;
    return (
      <div style={{
        height: '100%', width: '100%',
        background: 'var(--term-bg)',
        color: 'var(--t-muted)',
        fontFamily: 'JetBrains Mono, monospace',
        fontSize: 12,
        display: 'grid', placeItems: 'center', borderRadius: 8,
      }}>
        <div>· {name} not loaded ·</div>
      </div>
    );
  };

  return (
    <DesignCanvas>
      <DCSection id="entry" title="Entry · shell + meta" subtitle="land here · /help · /auth · /config · /workspace">
        <DCArtboard id="catalog"   label="catalog · `kuzushi` (no args)"   width={W} height={640}>{Slot('CatalogView')}</DCArtboard>
        <DCArtboard id="help"      label="help · /help"                    width={W} height={760}>{Slot('HelpView')}</DCArtboard>
        <DCArtboard id="auth"      label="auth · /auth · model picker"     width={W} height={680}>{Slot('AuthView')}</DCArtboard>
        <DCArtboard id="config"    label="config · /config show"           width={W} height={640}>{Slot('ConfigView')}</DCArtboard>
        <DCArtboard id="workspace" label="workspace · /workspace status"   width={W} height={760}>{Slot('WorkspaceView')}</DCArtboard>
      </DCSection>

      <DCSection id="intel" title="Intel" subtitle="context · recon · threat-model · randori">
        <DCArtboard id="context"      label="context · /run build"             width={W} height={620}>{Slot('ContextView')}</DCArtboard>
        <DCArtboard id="recon"        label="recon · nmap → subdomain → fp"    width={W} height={780}>{Slot('ReconView')}</DCArtboard>
        <DCArtboard id="threat-model" label="threat-model · /threats build"    width={W} height={780}>{Slot('ThreatModelView')}</DCArtboard>
        <DCArtboard id="randori"      label="randori · pasta + threat-model"   width={W} height={760}>{Slot('RandoriView')}</DCArtboard>
      </DCSection>

      <DCSection id="sast" title="SAST · deterministic" subtitle="sast umbrella · semgrep · codeql · secrets · iac · deps">
        <DCArtboard id="sast-running" label="sast · /scan (in progress)"  width={W} height={780}>{Slot('SastInProgressView')}</DCArtboard>
        <DCArtboard id="sast"         label="sast · /scan (complete)"     width={W} height={820}>{Slot('SastView')}</DCArtboard>
        <DCArtboard id="semgrep"      label="semgrep · /run scan"         width={W} height={720}>{Slot('SemgrepView')}</DCArtboard>
        <DCArtboard id="codeql"       label="codeql · /run scan"          width={W} height={760}>{Slot('CodeqlView')}</DCArtboard>
        <DCArtboard id="secret-scan"  label="secret-scan · /run scan"     width={W} height={680}>{Slot('SecretScanView')}</DCArtboard>
        <DCArtboard id="iac-scan"     label="iac-scan · tf + k8s + docker" width={W} height={780}>{Slot('IacScanView')}</DCArtboard>
        <DCArtboard id="dep-hygiene"  label="dep-hygiene · check"          width={W} height={780}>{Slot('DepHygieneView')}</DCArtboard>
      </DCSection>

      <DCSection id="agentic" title="Agentic offense" subtitle="carlini · agentic-sast · taint-iris · variant · ndiff">
        <DCArtboard id="carlini-running"      label="carlini · h2 in flight"             width={W} height={780}>{Slot('CarliniInProgressView')}</DCArtboard>
        <DCArtboard id="carlini"              label="carlini · complete"                  width={W} height={820}>{Slot('CarliniView')}</DCArtboard>
        <DCArtboard id="agentic-sast-running" label="agentic-sast · variant hunt in flight" width={W} height={820}>{Slot('AgenticSastInProgressView')}</DCArtboard>
        <DCArtboard id="agentic-sast"         label="agentic-sast · complete"             width={W} height={860}>{Slot('AgenticSastView')}</DCArtboard>
        <DCArtboard id="taint-iris"           label="taint-iris · hunt"                   width={W} height={760}>{Slot('TaintIrisView')}</DCArtboard>
        <DCArtboard id="taint-iris-next"      label="taint-iris-next · cross-lang"        width={W} height={780}>{Slot('TaintIrisNextView')}</DCArtboard>
        <DCArtboard id="variant"              label="variant · lift + hunt"               width={W} height={680}>{Slot('VariantView')}</DCArtboard>
        <DCArtboard id="ndiff"                label="ndiff · CVE → variant hunt"          width={W} height={720}>{Slot('NdiffView')}</DCArtboard>
      </DCSection>

      <DCSection id="defense" title="Defense · finding lifecycle" subtitle="triage · verify · patch · findings ledger">
        <DCArtboard id="triage"   label="triage · /run F-0001"            width={W} height={680}>{Slot('TriageView')}</DCArtboard>
        <DCArtboard id="verify"   label="verify · /run F-0001 --rerun"     width={W} height={720}>{Slot('VerifyView')}</DCArtboard>
        <DCArtboard id="patch"    label="patch · /run F-0001 --staged"     width={W} height={760}>{Slot('PatchView')}</DCArtboard>
        <DCArtboard id="findings" label="findings · /findings"             width={W} height={780}>{Slot('FindingsView')}</DCArtboard>
      </DCSection>

      <DCSection id="states" title="States · errors · dialogs" subtitle="how things look when they go sideways or need approval">
        <DCArtboard id="err-no-model"   label="error · no model configured"   width={W} height={620}>{Slot('ErrNoModelView')}</DCArtboard>
        <DCArtboard id="err-no-binary"  label="error · codeql binary missing" width={W} height={640}>{Slot('ErrNoBinaryView')}</DCArtboard>
        <DCArtboard id="err-no-plugin"  label="error · ToB plugin missing"    width={W} height={640}>{Slot('ErrNoPluginView')}</DCArtboard>
        <DCArtboard id="pause-resume"   label="state · paused · /resume"      width={W} height={780}>{Slot('PauseResumeView')}</DCArtboard>
        <DCArtboard id="agent-chat"     label="state · agent-chat (?text)"    width={W} height={760}>{Slot('AgentChatView')}</DCArtboard>
        <DCArtboard id="plain-mode"     label="state · --plain · ascii"       width={W} height={780}>{Slot('PlainModeView')}</DCArtboard>
        <DCArtboard id="confirm-dialog" label="dialog · confirm / refuse"     width={W} height={760}>{Slot('ConfirmDialogView')}</DCArtboard>
        <DCArtboard id="empty-states"   label="empty states · 4 panels"       width={W} height={840}>{Slot('EmptyStatesView')}</DCArtboard>
        <DCArtboard id="onboarding"     label="first run · onboarding"        width={W} height={760}>{Slot('OnboardingView')}</DCArtboard>
        <DCArtboard id="update-available" label="update · 0.18.2 → 0.19.0"    width={W} height={780}>{Slot('UpdateAvailableView')}</DCArtboard>
      </DCSection>

      <DCSection id="config" title="Config · option mutation" subtitle="/set · /setg · /actor · /auth · /workspace · /budget">
        <DCArtboard id="options-set"      label="/set · /setg · diff preview"   width={W} height={720}>{Slot('OptionsSetView')}</DCArtboard>
        <DCArtboard id="module-options"   label="/show options carlini"          width={W} height={760}>{Slot('ModuleOptionsView')}</DCArtboard>
        <DCArtboard id="actor-bind"       label="/actor · 8-role binding"        width={W} height={760}>{Slot('ActorBindView')}</DCArtboard>
        <DCArtboard id="auth-oauth"       label="/auth login · in flight"        width={W} height={680}>{Slot('AuthOauthView')}</DCArtboard>
        <DCArtboard id="auth-success"     label="/auth login · success"          width={W} height={700}>{Slot('AuthSuccessView')}</DCArtboard>
        <DCArtboard id="workspace-manage" label="/workspace · list / archive"    width={W} height={780}>{Slot('WorkspaceManageView')}</DCArtboard>
        <DCArtboard id="run-controls"     label="/budget · /cap · prompts"        width={W} height={780}>{Slot('RunControlsView')}</DCArtboard>
      </DCSection>

      <DCSection id="lifecycle-ext" title="Findings · patch · narration" subtitle="/findings filter · /use patch · /story">
        <DCArtboard id="findings-filter"  label="/findings · filter pivot"        width={W} height={780}>{Slot('FindingsFilterView')}</DCArtboard>
        <DCArtboard id="patch-review"     label="/use patch · staged review"      width={W} height={820}>{Slot('PatchReviewView')}</DCArtboard>
        <DCArtboard id="patch-conflict"   label="patch · CONFLICT (3-way)"        width={W} height={780}>{Slot('PatchConflictView')}</DCArtboard>
        <DCArtboard id="story"            label="/story · triage memo"            width={W} height={760}>{Slot('StoryView')}</DCArtboard>
        <DCArtboard id="deep-auditor"     label="deep-auditor · narrative"        width={W} height={780}>{Slot('DeepAuditorView')}</DCArtboard>
        <DCArtboard id="agent-router"     label="/agent-router · gates"           width={W} height={760}>{Slot('AgentRouterView')}</DCArtboard>
      </DCSection>

      <DCSection id="inspect" title="Inspect · trace · replay" subtitle="every run + every turn + every frame">
        <DCArtboard id="trace"           label="/trace · turn drill-down"     width={W} height={760}>{Slot('TraceView')}</DCArtboard>
        <DCArtboard id="run-inspect"     label="/show run r-2113"             width={W} height={780}>{Slot('RunInspectView')}</DCArtboard>
        <DCArtboard id="replay-scrub"    label="/replay · frame scrubber"     width={W} height={720}>{Slot('ReplayScrubView')}</DCArtboard>
        <DCArtboard id="doctor-failing"  label="doctor · 5 fail · 4 warn"     width={W} height={840}>{Slot('DoctorFailingView')}</DCArtboard>
        <DCArtboard id="kb-pull"         label="/kb pull · 41 new"            width={W} height={760}>{Slot('KbPullView')}</DCArtboard>
        <DCArtboard id="load-gh"         label="/load gh:…#PR412"             width={W} height={760}>{Slot('LoadGhView')}</DCArtboard>
        <DCArtboard id="history-search"  label="/history · fuzzy"             width={W} height={780}>{Slot('HistorySearchView')}</DCArtboard>
        <DCArtboard id="cost-breakdown"  label="/cost · per-actor"            width={W} height={780}>{Slot('CostBreakdownView')}</DCArtboard>
      </DCSection>

      <DCSection id="sandbox-net" title="Sandbox · network" subtitle="firejail · docker · allowlist · proxies">
        <DCArtboard id="sandbox-states"     label="/sandbox · status"          width={W} height={840}>{Slot('SandboxStatesView')}</DCArtboard>
        <DCArtboard id="network-allowlist"  label="/allowlist · 12 rules"      width={W} height={760}>{Slot('NetworkAllowlistView')}</DCArtboard>
        <DCArtboard id="findings-empty-match" label="/findings · 0 match"      width={W} height={680}>{Slot('FindingsEmptyMatchView')}</DCArtboard>
        <DCArtboard id="multi-target"       label="/workspace --multi"          width={W} height={780}>{Slot('MultiTargetView')}</DCArtboard>
        <DCArtboard id="threat-model-diff"  label="threat-model · v2..v3"       width={W} height={780}>{Slot('ThreatModelDiffView')}</DCArtboard>
      </DCSection>

      <DCSection id="module-states" title="Specialty module states" subtitle="x-ray scanning · chrome-rce no-target · prompt-armor red flag · triage queue · patch applied">
        <DCArtboard id="x-ray-scanning"        label="x-ray · in flight"        width={W} height={780}>{Slot('XrayScanningView')}</DCArtboard>
        <DCArtboard id="chrome-rce-no-target"  label="chrome-rce · no target"   width={W} height={720}>{Slot('ChromeRceNoTargetView')}</DCArtboard>
        <DCArtboard id="prompt-armor-red-flag" label="prompt-armor · RED FLAG"   width={W} height={780}>{Slot('PromptArmorRedFlagView')}</DCArtboard>
        <DCArtboard id="triage-queue"          label="/triage queue · live"      width={W} height={780}>{Slot('TriageQueueView')}</DCArtboard>
        <DCArtboard id="patch-applied"         label="patch · APPLIED"           width={W} height={780}>{Slot('PatchAppliedView')}</DCArtboard>
      </DCSection>

      <DCSection id="lifecycle-states" title="Lifecycle · in-flight · refusals · budget" subtitle="ndiff · verify-sandbox · audit · chat · tail · snapshot · export · secrets · deps · iac · refused · budget · kb · catalog-recent">
        <DCArtboard id="ndiff-running"      label="ndiff · in flight"             width={W} height={780}>{Slot('NdiffRunningView')}</DCArtboard>
        <DCArtboard id="verify-sandbox"     label="verify · sandbox spinning"     width={W} height={760}>{Slot('VerifySandboxView')}</DCArtboard>
        <DCArtboard id="vuln-scout-audit"   label="vuln-scout · audit ledger"     width={W} height={840}>{Slot('VulnScoutAuditView')}</DCArtboard>
        <DCArtboard id="agent-chat-stream"  label="/chat · streaming"             width={W} height={820}>{Slot('AgentChatStreamView')}</DCArtboard>
        <DCArtboard id="tail-stream"        label="/tail · live logs"             width={W} height={780}>{Slot('TailStreamView')}</DCArtboard>
        <DCArtboard id="snapshot-rollback"  label="/snapshot · rollback"          width={W} height={820}>{Slot('SnapshotRollbackView')}</DCArtboard>
        <DCArtboard id="export-bundle"      label="/export bundle · triage"       width={W} height={780}>{Slot('ExportBundleView')}</DCArtboard>
        <DCArtboard id="secrets-hits"       label="secret-scan · 3 hits"          width={W} height={780}>{Slot('SecretsHitsView')}</DCArtboard>
        <DCArtboard id="dep-upgrade"        label="dep-hygiene · upgrade plan"    width={W} height={840}>{Slot('DepUpgradeView')}</DCArtboard>
        <DCArtboard id="iac-crit"           label="iac-scan · 14 hits · 2 crit"   width={W} height={820}>{Slot('IacCritView')}</DCArtboard>
        <DCArtboard id="agent-refused"      label="agent · REFUSED · policy"      width={W} height={760}>{Slot('AgentRefusedView')}</DCArtboard>
        <DCArtboard id="budget-stop"        label="BUDGET · hard stop"             width={W} height={780}>{Slot('BudgetStopView')}</DCArtboard>
        <DCArtboard id="kb-show"            label="/kb show · CVE detail"          width={W} height={760}>{Slot('KbShowView')}</DCArtboard>
        <DCArtboard id="catalog-recent"     label="catalog · recent + active"      width={W} height={840}>{Slot('CatalogRecentView')}</DCArtboard>
      </DCSection>

      <DCSection id="more-flows" title="More flows · share · diff · inspect · palette · errors" subtitle="share-gen · diff-workspace · run-inspect · vendor-sbom · chrome-rce-target · quit · keymap · palette · rate-limit · net-down">
        <DCArtboard id="share-gen"          label="/share gen · signed url"        width={W} height={760}>{Slot('ShareGenView')}</DCArtboard>
        <DCArtboard id="diff-workspace"     label="/diff workspace · vs main+snap"  width={W} height={820}>{Slot('DiffWorkspaceView')}</DCArtboard>
        <DCArtboard id="vendor-sbom"        label="vendor-assessment · sbom"        width={W} height={820}>{Slot('VendorSbomView')}</DCArtboard>
        <DCArtboard id="chrome-rce-target"  label="chrome-rce · target picker"      width={W} height={820}>{Slot('ChromeRceTargetView')}</DCArtboard>
        <DCArtboard id="quit-confirm"       label="/quit · with dirty work"         width={W} height={780}>{Slot('QuitConfirmView')}</DCArtboard>
        <DCArtboard id="keymap"             label="/help · keymap"                  width={W} height={820}>{Slot('KeymapView')}</DCArtboard>
        <DCArtboard id="command-palette"    label="Ctrl-P · palette"                width={W} height={780}>{Slot('CommandPaletteView')}</DCArtboard>
        <DCArtboard id="rate-limited"       label="model rate-limited · 429"        width={W} height={760}>{Slot('RateLimitedView')}</DCArtboard>
        <DCArtboard id="network-down"       label="network down · partial"          width={W} height={780}>{Slot('NetworkDownView')}</DCArtboard>
        <DCArtboard id="theme-picker"       label="theme picker · 8 built-in"       width={W} height={820}>{Slot('ThemePickerView')}</DCArtboard>
      </DCSection>

      <DCSection id="ops-extras" title="Ops · ledger · schedule · tools · plan · kb · pre-commit" subtitle="every run · cron · mcp servers · agent plan-then-run · cross-source kb · git hook">
        <DCArtboard id="runs-list"          label="/runs · 114 in ledger"           width={W} height={840}>{Slot('RunsListView')}</DCArtboard>
        <DCArtboard id="schedule"           label="/schedule · 6 jobs"              width={W} height={840}>{Slot('ScheduleView')}</DCArtboard>
        <DCArtboard id="mcp-tools"          label="/mcp list · 5 servers"           width={W} height={820}>{Slot('McpToolsView')}</DCArtboard>
        <DCArtboard id="plan-preview"       label="agent · plan preview"            width={W} height={780}>{Slot('PlanPreviewView')}</DCArtboard>
        <DCArtboard id="kb-search"          label="/kb search · cross-source"       width={W} height={760}>{Slot('KbSearchView')}</DCArtboard>
        <DCArtboard id="pre-commit"         label="git pre-commit · BLOCKED"        width={W} height={780}>{Slot('PreCommitView')}</DCArtboard>
      </DCSection>

      <DCSection id="design-system" title="Design system" subtitle="type · color · glyphs · console-line · severity · banners · status-strip · footer · principles">
        <DCArtboard id="design-system" label="design-system · reference" width={W} height={1280}>{Slot('DesignSystemView')}</DCArtboard>
      </DCSection>

      <DCSection id="specialty" title="Specialty modules" subtitle="x-ray · chrome-rce · prompt-armor · vuln-scout · vendor · shinsa · tob">
        <DCArtboard id="x-ray"             label="x-ray · oci image surface map"  width={W} height={760}>{Slot('XrayView')}</DCArtboard>
        <DCArtboard id="chrome-rce"        label="chrome-rce · scan + trigger"    width={W} height={760}>{Slot('ChromeRceView')}</DCArtboard>
        <DCArtboard id="prompt-armor"      label="prompt-armor · attack matrix"   width={W} height={780}>{Slot('PromptArmorView')}</DCArtboard>
        <DCArtboard id="vuln-scout"        label="vuln-scout · audit ledger"      width={W} height={760}>{Slot('VulnScoutView')}</DCArtboard>
        <DCArtboard id="vendor-assessment" label="vendor-assessment · SegmentPay" width={W} height={780}>{Slot('VendorAssessmentView')}</DCArtboard>
        <DCArtboard id="shinsa"            label="shinsa · framework scan"        width={W} height={720}>{Slot('ShinsaView')}</DCArtboard>
        <DCArtboard id="tob"               label="tob · skills audit"             width={W} height={720}>{Slot('TobView')}</DCArtboard>
      </DCSection>
    </DesignCanvas>
  );
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);
