export interface ShellInputSegments {
  prompt: string;
  beforeCursor: string;
  cursorText: string;
  afterCursor: string;
}

export interface ShellInputRenderOptions {
  prompt: string;
  input: string;
  cursor: number;
  columns: number;
  cursorGlyph: string;
}

/**
 * Render the shell prompt as a single terminal row.
 *
 * Ink wraps long <Text> nodes by default; for an interactive prompt that makes
 * the buffer jump below `kuzushi/<module>`. This helper keeps the prompt line
 * bounded to the terminal width and horizontally scrolls the editable text.
 */
export function renderShellInputSegments({
  prompt,
  input,
  cursor,
  columns,
  cursorGlyph,
}: ShellInputRenderOptions): ShellInputSegments {
  const width = normalizeColumns(columns);
  const minEditorWidth = Math.min(2, width);
  const fittedPrompt = fitPrompt(prompt, Math.max(0, width - minEditorWidth));
  const editorWidth = Math.max(1, width - fittedPrompt.length);
  const boundedCursor = Math.max(0, Math.min(cursor, input.length));
  const cursorText = boundedCursor < input.length ? input[boundedCursor] : cursorGlyph;
  const visualLine =
    boundedCursor < input.length
      ? input.slice(0, boundedCursor) + cursorText + input.slice(boundedCursor + 1)
      : input + cursorText;
  const cursorIndex = boundedCursor;
  const start = computeWindowStart(visualLine.length, cursorIndex, editorWidth);
  const visible = visualLine.slice(start, start + editorWidth);
  const visibleCursor = Math.max(0, Math.min(cursorIndex - start, visible.length - 1));

  return {
    prompt: fittedPrompt,
    beforeCursor: visible.slice(0, visibleCursor),
    cursorText: visible[visibleCursor] ?? cursorGlyph,
    afterCursor: visible.slice(visibleCursor + 1),
  };
}

function normalizeColumns(columns: number): number {
  if (!Number.isFinite(columns) || columns <= 0) return 80;
  return Math.max(1, Math.floor(columns));
}

function fitPrompt(prompt: string, maxColumns: number): string {
  if (maxColumns <= 0) return "";
  if (prompt.length <= maxColumns) return prompt;
  if (maxColumns <= 4) return prompt.slice(0, maxColumns);

  const suffix = prompt.endsWith("> ") ? "> " : "";
  const bodyColumns = maxColumns - suffix.length;
  if (bodyColumns <= 3) return prompt.slice(0, maxColumns);
  return `${prompt.slice(0, bodyColumns - 3)}...${suffix}`;
}

function computeWindowStart(lineLength: number, cursorIndex: number, width: number): number {
  if (lineLength <= width) return 0;
  const maxStart = Math.max(0, lineLength - width);
  const cursorMargin = Math.max(0, Math.floor((width - 1) / 2));
  return Math.min(maxStart, Math.max(0, cursorIndex - cursorMargin));
}
