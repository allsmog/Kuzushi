/**
 * ThreatDfdView — attack-surface workspace.
 *
 * This is intentionally more than a static DFD. It turns the generated
 * context/threat model into an operator navigation surface: zones, trust
 * boundaries, hot paths, selected node detail, regeneration affordances, and
 * reviewable AI patches.
 */

import { Box, Text } from "ink";
import type React from "react";
import {
  type AttackSurfaceDfdModel,
  type AttackSurfaceFlow,
  type AttackSurfaceNode,
  deriveAttackSurfaceDfdModel,
  flowsForNode,
  selectedAttackSurfaceNode,
} from "../../attack-surface-dfd.js";
import { formatThreatModelSource } from "../../copilot/threat-model-loader.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { Table } from "../primitives/Table.js";
import type { ShellState } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { RuleHeader } from "./RuleHeader.js";
import { ScreenContent } from "./ScreenContent.js";

interface ThreatDfdViewProps {
  shell: ShellState;
}

export function ThreatDfdView({ shell }: ThreatDfdViewProps): React.ReactElement {
  useRegisterKeybindings([
    { keys: "1", label: "dfd" },
    { keys: "2", label: "stride", secondary: true },
    { keys: "3", label: "stories", secondary: true },
    { keys: "4", label: "scope", secondary: true },
    { keys: "5", label: "summary", secondary: true },
    { keys: "r", label: "regen", secondary: true },
    { keys: "q", label: "back", secondary: true },
  ]);

  const sourceLabel = shell.threatModelSource
    ? formatThreatModelSource({
        sourcePath: shell.threatModelSource.path,
        mtimeMs: shell.threatModelSource.mtimeMs,
      })
    : undefined;
  const model = deriveAttackSurfaceDfdModel({
    threatModel: shell.threatModel,
    contextSnapshot: shell.contextSnapshot,
    sourceKind: shell.threatModelSource?.path.endsWith("context-snapshot.json")
      ? "context"
      : shell.threatModel
        ? "persistent"
        : shell.contextSnapshot
          ? "context"
          : "empty",
    sourceLabel,
    selectedId: shell.threatDfdSelection,
  });

  const status = [
    `${model.nodes.length} nodes`,
    `${model.flows.length} flows`,
    `${model.boundaries.length} boundaries`,
    `${model.stats.threats} threats`,
  ].join(" · ");
  return (
    <ScreenContent>
      <RuleHeader breadcrumb="kuzushi/threats/dfd" status={status} rule={false} />
      {model.sourceLabel ? (
        <Box marginBottom={SPACING.sm}>
          <Text>{tokens.muted(formatSourceLine(model))}</Text>
        </Box>
      ) : null}
      {model.qualityNotice ? <QualityNotice notice={model.qualityNotice} /> : null}
      {model.nodes.length === 0 ? <EmptyWorkspace /> : <AttackSurfaceMap model={model} />}
      <SelectedPanel model={model} />
      <StrideOverlay model={model} />
      {shell.contextRegenPaletteOpen ? (
        <RegenerationPalette stale={shell.contextSnapshot?.staleSlices} />
      ) : null}
      {shell.pendingThreatPatch ? <PatchProposalCard shell={shell} /> : null}
      <ControlHint hasPatch={Boolean(shell.pendingThreatPatch)} />
    </ScreenContent>
  );
}

function formatSourceLine(model: AttackSurfaceDfdModel): string {
  if (model.basis === "app-model-inferred") {
    const loadedPrefix = "loaded from ";
    const source = model.sourceLabel.startsWith(loadedPrefix)
      ? model.sourceLabel.slice(loadedPrefix.length)
      : model.sourceLabel;
    return `inferred from ${source}`;
  }
  return model.sourceLabel;
}

function QualityNotice({ notice }: { notice: string }): React.ReactElement {
  return (
    <Box marginBottom={SPACING.sm}>
      <Text>{tokens.warn(notice)}</Text>
    </Box>
  );
}

function EmptyWorkspace(): React.ReactElement {
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.warn("No threat-model DFD is available yet.")}</Text>
      <Text>{tokens.muted("Run /context, then /threats regen dfd, or use /threats edit.")}</Text>
    </Box>
  );
}

function AttackSurfaceMap({ model }: { model: AttackSurfaceDfdModel }): React.ReactElement {
  const nodeRows = model.zones.flatMap((zone) =>
    zone.nodes.map((node) => ({
      zone: zone.title,
      id: node.id,
      type: nodeGlyph(node),
      node: node.name,
      risk: node.risk,
      detail: node.tags.length > 0 ? node.tags.slice(0, 3).join(" · ") : node.description,
      selected: node.id === model.selectedId,
    })),
  );
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Section title="zones">
        <Table
          showHeader
          divider={false}
          gap={2}
          columns={[
            { key: "zone", header: "zone", flex: 2, truncate: "end" },
            { key: "id", header: "id", width: 5 },
            { key: "type", header: "type", width: 8 },
            {
              key: "node",
              header: "node",
              flex: 3,
              truncate: "end",
              render: (row: (typeof nodeRows)[number]) =>
                row.selected ? tokens.accent(row.node) : row.node,
            },
            {
              key: "risk",
              header: "risk",
              width: 8,
              render: (row: (typeof nodeRows)[number]) => riskToken(row.risk),
            },
            { key: "detail", header: "detail", flex: 4, truncate: "end" },
          ]}
          rows={nodeRows}
        />
      </Section>
      {model.boundaries.length > 0 ? <BoundariesBlock model={model} /> : null}
      {model.flows.length > 0 ? <FlowsBlock model={model} /> : null}
    </Box>
  );
}

function BoundariesBlock({ model }: { model: AttackSurfaceDfdModel }): React.ReactElement {
  const rows = model.boundaries.map((boundary) => ({
    id: boundary.id,
    name: boundary.name,
    from: boundary.from,
    to: boundary.to,
    crossing: String(boundary.crossingFlows.length),
  }));
  return (
    <Section title="boundaries">
      <Table
        showHeader
        divider={false}
        gap={2}
        columns={[
          {
            key: "id",
            header: "id",
            width: 8,
            render: (row: (typeof rows)[number]) => tokens.warn(row.id),
          },
          { key: "name", header: "name", flex: 3, truncate: "end" },
          { key: "from", header: "from", flex: 2, truncate: "end" },
          { key: "to", header: "to", flex: 2, truncate: "end" },
          { key: "crossing", header: "flows", width: 6, align: "right" },
        ]}
        rows={rows}
      />
    </Section>
  );
}

function FlowsBlock({ model }: { model: AttackSurfaceDfdModel }): React.ReactElement {
  const hot = model.flows.filter((flow) => flow.hot).slice(0, 5);
  const shown = hot.length > 0 ? hot : model.flows.slice(0, 5);
  const rows = shown.map((flow) => ({
    risk: flow.hot ? "hot" : "watch",
    from: flow.source,
    to: flow.target,
    protocol: flow.protocol ?? "",
    data: flow.dataClassification ?? "",
    crosses: flow.crosses.length > 0 ? flow.crosses.join(",") : "",
  }));
  return (
    <Section title="flows">
      <Table
        showHeader
        divider={false}
        gap={2}
        columns={[
          {
            key: "risk",
            header: "risk",
            width: 8,
            render: (row: (typeof rows)[number]) => riskToken(row.risk),
          },
          { key: "from", header: "from", flex: 2, truncate: "end" },
          { key: "to", header: "to", flex: 2, truncate: "end" },
          { key: "protocol", header: "protocol", flex: 1, truncate: "end" },
          { key: "data", header: "data", flex: 2, truncate: "end" },
          { key: "crosses", header: "boundary", flex: 2, truncate: "end" },
        ]}
        rows={rows}
      />
    </Section>
  );
}

function SelectedPanel({ model }: { model: AttackSurfaceDfdModel }): React.ReactElement | null {
  const node = selectedAttackSurfaceNode(model);
  if (!node) return null;
  const flows = flowsForNode(model, node.id);
  const risks = node.tags.length > 0 ? node.tags.join(" · ") : node.description;
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label("selected")}</Text>
      <FieldRow label="id" value={tokens.accent(`${node.id} ${node.name}`)} />
      <FieldRow label="zone" value={node.zone} />
      <FieldRow label="inputs" value={formatFlowEndpoints(flows.inputs, "source")} />
      <FieldRow label="outputs" value={formatFlowEndpoints(flows.outputs, "target")} />
      <FieldRow
        label="risks"
        value={node.risk === "hot" ? tokens.danger(risks) : tokens.warn(risks)}
      />
      <FieldRow label="next" value={model.nextActions.slice(0, 2).join(" · ")} />
    </Box>
  );
}

function StrideOverlay({ model }: { model: AttackSurfaceDfdModel }): React.ReactElement {
  const counts = model.strideCounts;
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label("STRIDE overlay")}</Text>
      <Box flexDirection="row" gap={2} paddingLeft={SPACING.md}>
        <Text>{tokens.value(`S:${counts.spoofing}`)}</Text>
        <Text>{tokens.value(`T:${counts.tampering}`)}</Text>
        <Text>{tokens.value(`R:${counts.repudiation}`)}</Text>
        <Text>{tokens.value(`I:${counts["information-disclosure"]}`)}</Text>
        <Text>{tokens.value(`D:${counts["denial-of-service"]}`)}</Text>
        <Text>{tokens.value(`E:${counts["elevation-of-privilege"]}`)}</Text>
      </Box>
      {model.stats.threats === 0 ? (
        <Box paddingLeft={SPACING.md}>
          <Text>
            {tokens.warn("no threats emitted; watch hot paths and privileged choke points")}
          </Text>
        </Box>
      ) : null}
    </Box>
  );
}

function RegenerationPalette({ stale }: { stale?: readonly string[] }): React.ReactElement {
  const staleLabel = stale && stale.length > 0 ? `stale: ${stale.join(", ")}` : "no stale slices";
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label("Regenerate threat-model slice")}</Text>
      <Box paddingLeft={SPACING.md}>
        <Text>{tokens.muted(staleLabel)}</Text>
      </Box>
      <Box paddingLeft={SPACING.md}>
        <Table
          showHeader={false}
          divider={false}
          gap={2}
          columns={[
            { key: "command", width: 28 },
            { key: "detail", flex: 1, truncate: "end" },
          ]}
          rows={[
            { command: "/context regen repo", detail: "repo/file signals" },
            { command: "/context regen app-model", detail: "routes, stores, boundaries" },
            { command: "/threats regen dfd", detail: "data-flow diagram" },
            { command: "/threats regen stride", detail: "STRIDE overlay" },
            { command: "/threats regen scenarios", detail: "downstream probes" },
          ]}
        />
      </Box>
    </Box>
  );
}

function PatchProposalCard({ shell }: { shell: ShellState }): React.ReactElement | null {
  const patch = shell.pendingThreatPatch;
  if (!patch) return null;
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label("AI proposed DFD patch")}</Text>
      <FieldRow label="instruction" value={patch.instruction} />
      <FieldRow label="summary" value={patch.summary} />
      {patch.diffLines.slice(0, 8).map((line) => (
        <Text key={line}>
          {line.startsWith("-")
            ? tokens.danger(line)
            : line.startsWith("+")
              ? tokens.accent(line)
              : tokens.warn(line)}
        </Text>
      ))}
      {patch.validationErrors.length > 0 ? (
        <Box paddingLeft={SPACING.md}>
          <Text>{tokens.warn(`warnings: ${patch.validationErrors.join(" · ")}`)}</Text>
        </Box>
      ) : null}
      <Box paddingLeft={SPACING.md}>
        <Text>{tokens.muted("y accept · n reject · /threats ask <revision>")}</Text>
      </Box>
    </Box>
  );
}

function ControlHint({ hasPatch }: { hasPatch: boolean }): React.ReactElement {
  if (!hasPatch) return <Box />;
  return (
    <Box marginTop={SPACING.sm}>
      <Text>{tokens.muted("patch proposal: y accept · n reject · /threats ask <revision>")}</Text>
    </Box>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}): React.ReactElement {
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label(title)}</Text>
      <Box marginTop={SPACING.xs} paddingLeft={SPACING.md}>
        {children}
      </Box>
    </Box>
  );
}

function FieldRow({ label, value }: { label: string; value: string }): React.ReactElement {
  return (
    <Box flexDirection="row" paddingLeft={SPACING.md}>
      <Box width={9}>
        <Text>{tokens.muted(label)}</Text>
      </Box>
      <Text>{tokens.value(value)}</Text>
    </Box>
  );
}

function riskToken(risk: string): string {
  if (risk === "hot") return tokens.danger("hot");
  if (risk === "watch") return tokens.warn("watch");
  return tokens.muted(risk || "normal");
}

function nodeGlyph(node: AttackSurfaceNode): string {
  switch (node.type) {
    case "external-entity":
      return "(ext)";
    case "process":
      return "[proc]";
    case "data-store":
      return "<<data>>";
  }
}

function formatFlowEndpoints(flows: AttackSurfaceFlow[], side: "source" | "target"): string {
  if (flows.length === 0) return "(none)";
  return flows
    .slice(0, 4)
    .map((flow) => flow[side])
    .join(" · ");
}
