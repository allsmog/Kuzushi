/**
 * Lightweight terminal markdown renderer.
 *
 * cc-repo uses a full CommonMark pipeline for assistant text. Kuzushi
 * has historically rendered assistant output as plain `<MultilineText>`.
 * This component covers the visual gap for the ~90% of assistant text
 * that uses only basic markdown constructs (bold, italic, inline code,
 * fenced code, headings, bullets, links) — without taking a new runtime
 * dependency.
 *
 * Anything this parser doesn't understand falls through as plain text,
 * so degradation is always graceful.
 */

import { Box, Text } from "ink";
import React from "react";
import { SPACING, tokens } from "../tokens.js";

interface MarkdownProps {
  text: string;
}

/**
 * Inline markdown — bold (`**x**`), italic (`*x*` / `_x_`), inline code
 * (`` `x` ``), and links (`[text](url)`). Rendered as a single flat
 * `<Text>` by splitting the input into styled segments.
 *
 * Order matters: code fences first so their delimiters don't get eaten
 * by bold/italic matchers.
 */
function renderInline(text: string, keyPrefix: string): React.ReactNode[] {
  const nodes: React.ReactNode[] = [];
  // Greedy regex union across the four inline forms. Group 1: code,
  // Group 2: bold, Group 3: italic-star, Group 4: italic-underscore,
  // Groups 5 & 6: link text + url.
  const RE = /`([^`]+)`|\*\*([^*]+)\*\*|\*([^*]+)\*|_([^_]+)_|\[([^\]]+)\]\(([^)]+)\)/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  let idx = 0;
  // biome-ignore lint/suspicious/noAssignInExpressions: standard regex exec loop
  while ((match = RE.exec(text)) !== null) {
    if (match.index > lastIndex) {
      nodes.push(text.slice(lastIndex, match.index));
    }
    const key = `${keyPrefix}-${idx++}`;
    if (match[1] != null) {
      nodes.push(
        <Text key={key} backgroundColor="gray" color="white">
          {match[1]}
        </Text>,
      );
    } else if (match[2] != null) {
      nodes.push(
        <Text key={key} bold>
          {match[2]}
        </Text>,
      );
    } else if (match[3] != null) {
      nodes.push(
        <Text key={key} italic>
          {match[3]}
        </Text>,
      );
    } else if (match[4] != null) {
      nodes.push(
        <Text key={key} italic>
          {match[4]}
        </Text>,
      );
    } else if (match[5] != null && match[6] != null) {
      nodes.push(
        <Text key={key}>
          <Text underline>{match[5]}</Text>
          {tokens.muted(` (${match[6]})`)}
        </Text>,
      );
    }
    lastIndex = RE.lastIndex;
  }
  if (lastIndex < text.length) {
    nodes.push(text.slice(lastIndex));
  }
  return nodes;
}

/**
 * Block-level markdown. Headings, bullets, numbered lists, fenced code
 * blocks, plus paragraph passthrough. Each line becomes one `<Text>`;
 * blank lines are preserved with an empty Text for vertical spacing.
 */
export function Markdown({ text }: MarkdownProps): React.ReactElement {
  const lines = text.split("\n");
  const blocks: React.ReactElement[] = [];
  let inCode = false;
  let codeBuffer: string[] = [];
  let codeKey = 0;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!;
    // Fenced code block toggle
    if (/^```/.test(raw.trim())) {
      if (inCode) {
        // Flush
        const key = `code-${codeKey++}`;
        const body = codeBuffer.join("\n");
        blocks.push(
          <Box key={key} flexDirection="column" paddingLeft={SPACING.md}>
            {body.split("\n").map((ln, j) => (
              <Text key={`${key}-${j}`}>{tokens.muted(ln)}</Text>
            ))}
          </Box>,
        );
        codeBuffer = [];
        inCode = false;
      } else {
        inCode = true;
      }
      continue;
    }
    if (inCode) {
      codeBuffer.push(raw);
      continue;
    }

    // Heading: `# foo`, `## foo`, `### foo`
    const headingMatch = /^(#{1,6})\s+(.+)$/.exec(raw);
    if (headingMatch) {
      const level = headingMatch[1]!.length;
      const body = headingMatch[2]!;
      blocks.push(
        <Text key={`h-${i}`} bold underline={level <= 2}>
          {body}
        </Text>,
      );
      continue;
    }

    // Bullet: `- foo` or `* foo`
    const bulletMatch = /^(\s*)[-*]\s+(.+)$/.exec(raw);
    if (bulletMatch) {
      const indent = bulletMatch[1]!.length;
      const body = bulletMatch[2]!;
      blocks.push(
        <Text key={`b-${i}`}>
          {" ".repeat(indent)}
          {tokens.muted("• ")}
          {renderInline(body, `b-${i}`)}
        </Text>,
      );
      continue;
    }

    // Numbered list: `1. foo`
    const numberedMatch = /^(\s*)(\d+)\.\s+(.+)$/.exec(raw);
    if (numberedMatch) {
      const indent = numberedMatch[1]!.length;
      const num = numberedMatch[2]!;
      const body = numberedMatch[3]!;
      blocks.push(
        <Text key={`n-${i}`}>
          {" ".repeat(indent)}
          {tokens.muted(`${num}. `)}
          {renderInline(body, `n-${i}`)}
        </Text>,
      );
      continue;
    }

    // Blank line — preserve vertical space
    if (raw.trim() === "") {
      blocks.push(<Text key={`s-${i}`}> </Text>);
      continue;
    }

    // Default: paragraph line with inline markdown
    blocks.push(<Text key={`p-${i}`}>{renderInline(raw, `p-${i}`)}</Text>);
  }

  // Trailing unclosed code block
  if (inCode && codeBuffer.length > 0) {
    const key = `code-${codeKey++}`;
    blocks.push(
      <Box key={key} flexDirection="column" paddingLeft={SPACING.md}>
        {codeBuffer.map((ln, j) => (
          <Text key={`${key}-${j}`}>{tokens.muted(ln)}</Text>
        ))}
      </Box>,
    );
  }

  return <Box flexDirection="column">{blocks}</Box>;
}
