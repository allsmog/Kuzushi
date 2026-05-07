const { DesignCanvas, DCSection, DCArtboard } = window;

function App() {
  // 120 cols × ~12.5px font ≈ 1080px wide; height ~ rows × 16px line-height
  const W = 1100;
  return (
    <DesignCanvas>
      <DCSection id="entry" title="Entry" subtitle="The view operators land in">
        <DCArtboard id="catalog" label="catalog · /help" width={W} height={640}>
          <window.CatalogView />
        </DCArtboard>
      </DCSection>

      <DCSection id="intel" title="Intel" subtitle="context · recon · threat-model">
        <DCArtboard id="context" label="context · /run build" width={W} height={620}>
          <window.ContextView />
        </DCArtboard>
        <DCArtboard id="recon" label="recon · nmap → subdomain → fp" width={W} height={780}>
          <window.ReconView />
        </DCArtboard>
        <DCArtboard id="threat-model" label="threat-model · /threats build" width={W} height={780}>
          <window.ThreatModelView />
        </DCArtboard>
      </DCSection>

      <DCSection id="offense" title="Offense" subtitle="sast · carlini · agentic-sast · in-flight + complete">
        <DCArtboard id="sast-running" label="sast · /scan (in progress)" width={W} height={780}>
          <window.SastInProgressView />
        </DCArtboard>
        <DCArtboard id="sast" label="sast · /scan (complete)" width={W} height={820}>
          <window.SastView />
        </DCArtboard>
        <DCArtboard id="carlini-running" label="carlini-threat-hunt · h2 in flight" width={W} height={780}>
          <window.CarliniInProgressView />
        </DCArtboard>
        <DCArtboard id="carlini" label="carlini-threat-hunt · complete" width={W} height={820}>
          <window.CarliniView />
        </DCArtboard>
        <DCArtboard id="agentic-sast-running" label="agentic-sast · variant hunt in flight" width={W} height={820}>
          <window.AgenticSastInProgressView />
        </DCArtboard>
        <DCArtboard id="agentic-sast" label="agentic-sast · complete" width={W} height={860}>
          <window.AgenticSastView />
        </DCArtboard>
      </DCSection>
    </DesignCanvas>
  );
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);
