/**
 * Lightweight terminal markdown renderer.
 *
 * Renders inline markdown to chalk-formatted strings for terminal display.
 * Supports: `inline code`, **bold**, *italic*, [links](url), bullet lists.
 * Does NOT support full block-level markdown (tables, code fences, blockquotes)
 * — those are overkill for finding rationale text.
 *
 * Inspired by CC's markdown.ts but much simpler — we only render inline
 * formatting within a single text string, not multi-line documents.
 */
import chalk from "chalk";
import { urlLink } from "./hyperlink.js";

/**
 * Render inline markdown to chalk-formatted terminal string.
 *
 * Handles:
 * - `code` → highlighted inline code
 * - **bold** → chalk bold
 * - *italic* → chalk italic
 * - [text](url) → OSC 8 hyperlink (or plain text fallback)
 * - CVE-XXXX-XXXXX → auto-linked to NVD
 * - CWE-XXX → auto-linked to MITRE
 */
export function renderMarkdownInline(text: string): string {
  let result = text;

  // Links: [text](url) → hyperlink or plain text
  result = result.replace(
    /\[([^\]]+)\]\(([^)]+)\)/g,
    (_match, linkText: string, url: string) => urlLink(url, chalk.underline(linkText)),
  );

  // Inline code: `code` → highlighted
  result = result.replace(
    /`([^`]+)`/g,
    (_match, code: string) => chalk.yellowBright(code),
  );

  // Bold: **text** → chalk bold
  result = result.replace(
    /\*\*([^*]+)\*\*/g,
    (_match, bold: string) => chalk.bold(bold),
  );

  // Italic: *text* → chalk italic (but not inside ** which was already handled)
  result = result.replace(
    /(?<!\*)\*([^*]+)\*(?!\*)/g,
    (_match, italic: string) => chalk.italic(italic),
  );

  // CVE references: CVE-2024-12345 → linked to NVD
  result = result.replace(
    /\b(CVE-\d{4}-\d{4,})\b/g,
    (_match, cve: string) => urlLink(`https://nvd.nist.gov/vuln/detail/${cve}`, chalk.cyan(cve)),
  );

  // CWE references: CWE-79 → linked to MITRE
  result = result.replace(
    /\b(CWE-\d+)\b/g,
    (_match, cwe: string) => urlLink(`https://cwe.mitre.org/data/definitions/${cwe.replace("CWE-", "")}.html`, chalk.cyan(cwe)),
  );

  return result;
}

/**
 * Render a multi-line text block with basic markdown.
 *
 * Handles inline formatting per line, plus:
 * - Lines starting with `- ` or `* ` → bullet points (•)
 * - Lines starting with `  - ` → nested bullets
 *
 * @param text - Raw markdown text
 * @param maxWidth - Max width per line (truncates with ...)
 * @returns Array of formatted lines
 */
export function renderMarkdownBlock(text: string, maxWidth = 120): string[] {
  const lines = text.split("\n");
  const result: string[] = [];

  for (const line of lines) {
    // Bullet lists
    const nestedBullet = line.match(/^(\s{2,})[-*]\s+(.+)/);
    if (nestedBullet) {
      const content = renderMarkdownInline(truncateLine(nestedBullet[2]!, maxWidth - 6));
      result.push(`    ${chalk.dim("·")} ${content}`);
      continue;
    }

    const bullet = line.match(/^[-*]\s+(.+)/);
    if (bullet) {
      const content = renderMarkdownInline(truncateLine(bullet[1]!, maxWidth - 4));
      result.push(`  ${chalk.dim("•")} ${content}`);
      continue;
    }

    // Regular line
    const content = renderMarkdownInline(truncateLine(line, maxWidth));
    result.push(content);
  }

  return result;
}

function truncateLine(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 3)}...`;
}
