/**
 * Interactive default-model picker.
 *
 * The first step picks the provider/backend; the second step shows only
 * models for that provider plus any operator-saved pool entries.
 */

import { Box, Text, useInput } from "ink";
import type React from "react";
import { useMemo, useState } from "react";
import {
  MODEL_PROVIDERS,
  type ModelCatalogEntry,
  modelOptionsForProvider,
  providerFromModelId,
} from "../../model-catalog.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { icons } from "../icons.js";
import { isCancelInput } from "../interaction-key-policy.js";
import {
  SelectList,
  type SelectListItem,
  type SelectListRenderContext,
} from "../primitives/SelectList.js";
import { SPACING, tokens } from "../tokens.js";

interface ModelPromptProps {
  activeModel?: string;
  availableModels?: ReadonlyArray<string>;
  credentialedProviders?: ReadonlyArray<string>;
  onComplete: (modelId: string) => void;
  onCancel: () => void;
}

type Step = "provider" | "model";

const PROVIDER_KEYBINDS = [
  { keys: "\u2191/\u2193", label: "Navigate" },
  { keys: "Enter", label: "Select" },
  { keys: "q", label: "Quit", secondary: true },
];

const MODEL_KEYBINDS = [
  { keys: "\u2191/\u2193", label: "Navigate" },
  { keys: "Enter", label: "Use" },
  { keys: "Esc", label: "Back", secondary: true },
  { keys: "q", label: "Quit", secondary: true },
];

export function ModelPrompt({
  activeModel,
  availableModels = [],
  credentialedProviders = [],
  onComplete,
  onCancel,
}: ModelPromptProps): React.ReactElement {
  const activeProvider = providerFromModelId(activeModel);
  const credentialed = useMemo(() => new Set(credentialedProviders), [credentialedProviders]);
  const [step, setStep] = useState<Step>("provider");
  const [provider, setProvider] = useState<string>(
    activeProvider ?? credentialedProviders[0] ?? MODEL_PROVIDERS[0]!.id,
  );

  useRegisterKeybindings(step === "provider" ? PROVIDER_KEYBINDS : MODEL_KEYBINDS);

  useInput(
    (input, key) => {
      if (input === "q") {
        onCancel();
        return;
      }
      if (isCancelInput(input, key)) {
        if (step === "model") setStep("provider");
        else onCancel();
      }
    },
    { isActive: true },
  );

  const providerItems = useMemo(
    () =>
      MODEL_PROVIDERS.map<SelectListItem<string>>((item) => ({
        id: item.id,
        label: item.name,
        detail: item.description,
      })),
    [],
  );

  const modelEntries = useMemo(
    () => modelOptionsForProvider(provider, { activeModel, availableModels }),
    [activeModel, availableModels, provider],
  );

  const modelItems = useMemo(
    () =>
      modelEntries.map<SelectListItem<string>>((item) => ({
        id: item.id,
        label: item.name,
        detail: item.description,
      })),
    [modelEntries],
  );

  const providerRenderer = (ctx: SelectListRenderContext<string>): React.ReactElement => {
    const item = MODEL_PROVIDERS.find((candidate) => candidate.id === ctx.item.id)!;
    const isActiveProvider = item.id === activeProvider;
    const hasCredentials = credentialed.has(item.id);
    const name = ctx.isCursor ? tokens.strong(item.name) : tokens.muted(item.name);
    const status = [
      isActiveProvider ? "active" : "",
      hasCredentials ? "credentials found" : "credentials not detected",
    ]
      .filter(Boolean)
      .join(" · ");

    return (
      <Box flexDirection="column" paddingLeft={SPACING.md}>
        <Text>
          {ctx.cursorPrefix} {hasCredentials ? icons.complete : icons.info} {name}{" "}
          {tokens.muted(`- ${item.description}`)}
        </Text>
        {ctx.isCursor && (
          <>
            <Box paddingLeft={SPACING.xxxl}>
              <Text>{tokens.muted(item.detail)}</Text>
            </Box>
            <Box paddingLeft={SPACING.xxxl}>
              <Text>{tokens.hint(status)}</Text>
            </Box>
          </>
        )}
      </Box>
    );
  };

  const modelRenderer = (ctx: SelectListRenderContext<string>): React.ReactElement => {
    const item = modelEntries.find((candidate) => candidate.id === ctx.item.id)!;
    return renderModelRow(ctx, item, item.id === activeModel);
  };

  return (
    <Box flexDirection="column">
      <Box paddingLeft={SPACING.md}>
        <Text>{tokens.label("Model")}</Text>
      </Box>
      <Box paddingLeft={SPACING.md}>
        <Text>
          {tokens.muted(
            step === "provider"
              ? "Choose the backend/provider to route the default model through."
              : `Choose the default model for ${provider}.`,
          )}
        </Text>
      </Box>
      {activeModel ? (
        <Box paddingLeft={SPACING.md}>
          <Text>{tokens.hint(`Active: ${activeModel}`)}</Text>
        </Box>
      ) : null}
      <Text>{""}</Text>

      {step === "provider" ? (
        <SelectList
          items={providerItems}
          selectedId={provider}
          onHighlight={setProvider}
          onSelect={(id) => {
            setProvider(id);
            setStep("model");
          }}
          renderItem={providerRenderer}
        />
      ) : (
        <SelectList
          items={modelItems}
          selectedId={activeModel}
          onSelect={onComplete}
          emptyMessage={`No curated models for ${provider}; use /model use <provider:model>.`}
          renderItem={modelRenderer}
        />
      )}
    </Box>
  );
}

function renderModelRow(
  ctx: SelectListRenderContext<string>,
  item: ModelCatalogEntry,
  isActiveModel: boolean,
): React.ReactElement {
  const name = ctx.isCursor ? tokens.strong(item.name) : tokens.muted(item.name);
  return (
    <Box flexDirection="column" paddingLeft={SPACING.md}>
      <Text>
        {ctx.cursorPrefix} {isActiveModel ? icons.active : icons.complete} {name}{" "}
        {tokens.muted(`- ${item.description}`)}
      </Text>
      {ctx.isCursor && (
        <>
          <Box paddingLeft={SPACING.xxxl}>
            <Text>{tokens.muted(item.detail)}</Text>
          </Box>
          <Box paddingLeft={SPACING.xxxl}>
            <Text>{tokens.strong(item.summary)}</Text>
          </Box>
          <Box paddingLeft={SPACING.xxxl}>
            <Text>{tokens.hint(item.id)}</Text>
          </Box>
        </>
      )}
    </Box>
  );
}
