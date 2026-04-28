import { Box, Text } from "ink";
import type React from "react";
import { useRegisterKeybindings } from "../../hooks/useKeybindings.js";
import { Table } from "../../primitives/Table.js";
import { SPACING, tokens } from "../../tokens.js";
import { RuleHeader } from "../RuleHeader.js";
import { ScreenContent } from "../ScreenContent.js";
import { KeyValueSection } from "./context-home.js";
import type { ModuleHomeProps } from "./types.js";

const MODULE_ID = "vendor-assessment";

export function VendorAssessmentHome({ shell }: ModuleHomeProps): React.ReactElement {
  useRegisterKeybindings([
    { keys: "Enter", label: "type tool verb" },
    { keys: "t", label: "tune", secondary: true },
    { keys: "b", label: "back", secondary: true },
    { keys: "?", label: "help", secondary: true },
  ]);

  const slice = shell.vendorAssessment;
  const docs = slice?.documents ?? [];
  const missing = slice?.missingArtifacts ?? [];
  return (
    <ScreenContent>
      <RuleHeader breadcrumb={`kuzushi/${MODULE_ID}`} status="draft scope" />
      <KeyValueSection
        title="status"
        rows={[
          { key: "vendor", value: slice?.vendorName ?? "(not set)" },
          { key: "profile", value: slice?.profile ?? "enterprise-ai" },
          { key: "confidence", value: slice?.confidence ?? "empty" },
          { key: "docs", value: `${docs.length} attached` },
          { key: "missing", value: missing.length > 0 ? missing.join(", ") : "(none)" },
        ]}
      />
      <DocumentsBlock docs={docs} />
      <ActionsBlock />
      {slice?.lastRun ? (
        <KeyValueSection
          title="last run"
          rows={[
            { key: "run", value: slice.lastRun.runId },
            { key: "risk", value: slice.lastRun.overallRisk },
            { key: "report", value: slice.lastRun.reportPath },
          ]}
        />
      ) : null}
    </ScreenContent>
  );
}

function DocumentsBlock({
  docs,
}: {
  docs: NonNullable<NonNullable<ModuleHomeProps["shell"]["vendorAssessment"]>["documents"]>;
}): React.ReactElement {
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label("documents")}</Text>
      <Box paddingLeft={SPACING.md} marginTop={SPACING.xs}>
        {docs.length === 0 ? (
          <Text>{tokens.muted("(none attached)")}</Text>
        ) : (
          <Table
            showHeader={false}
            divider={false}
            gap={2}
            columns={[
              { key: "status", flex: 1, truncate: "end" },
              { key: "title", flex: 4, truncate: "middle" },
              { key: "kind", flex: 2, truncate: "end" },
              { key: "detail", flex: 3, truncate: "end" },
            ]}
            rows={docs.map((doc) => ({
              status: doc.status === "parsed" ? "[x]" : doc.status === "error" ? "[!]" : "[ ]",
              title: doc.title,
              kind: doc.kind,
              detail: doc.detail,
            }))}
          />
        )}
      </Box>
    </Box>
  );
}

function ActionsBlock(): React.ReactElement {
  return (
    <KeyValueSection
      title="actions"
      rows={[
        {
          key: "attach <path-or-url>",
          value: "add a questionnaire, diagram, transcript, contract, or policy",
        },
        { key: "scope", value: "show current draft scope" },
        { key: "clear scope", value: "clear current draft scope" },
        { key: "assess vendor=<name>", value: "generate local report artifacts" },
        { key: "prompts", value: "write downstream-agent prompt bundle" },
      ]}
    />
  );
}
