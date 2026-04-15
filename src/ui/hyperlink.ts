/**
 * OSC 8 terminal hyperlink support.
 *
 * Makes file paths clickable in supported terminals (iTerm2, Windows Terminal,
 * VS Code terminal, GNOME Terminal, etc.). Click a finding location → opens
 * the file in the user's editor at the right line.
 *
 * Falls back to plain text in unsupported terminals.
 */
import { pathToFileURL } from "node:url";
import path from "node:path";

const OSC8_START = "\x1b]8;;";
const OSC8_END = "\x07"; // BEL terminator — more widely supported than ST (\x1b\\)

let _supportsLinks: boolean | null = null;

/**
 * Detect whether the terminal supports OSC 8 hyperlinks.
 *
 * Checks TERM_PROGRAM and FORCE_HYPERLINKS env vars. Cached after first call.
 */
export function supportsHyperlinks(): boolean {
  if (_supportsLinks !== null) return _supportsLinks;

  if (process.env["FORCE_HYPERLINKS"] === "1") {
    _supportsLinks = true;
    return true;
  }
  if (process.env["FORCE_HYPERLINKS"] === "0") {
    _supportsLinks = false;
    return false;
  }

  // Known-good terminals
  const term = process.env["TERM_PROGRAM"] ?? "";
  const supported = [
    "iTerm.app",
    "WezTerm",
    "vscode",        // VS Code integrated terminal
    "Hyper",
    "mintty",        // Git Bash / MSYS2
  ];

  // Windows Terminal sets WT_SESSION
  if (process.env["WT_SESSION"]) {
    _supportsLinks = true;
    return true;
  }

  _supportsLinks = supported.some((t) => term.includes(t));
  return _supportsLinks;
}

/**
 * Wrap text in an OSC 8 hyperlink to a file path.
 *
 * @param filePath - Relative or absolute file path
 * @param displayText - Text to display (defaults to filePath)
 * @param line - Optional line number (appended as #L{line} for editor integration)
 * @param repoRoot - Optional repo root for resolving relative paths
 * @returns Hyperlinked text, or plain text if unsupported
 */
export function fileLink(
  filePath: string,
  displayText?: string,
  line?: number,
  repoRoot?: string,
): string {
  const text = displayText ?? (line ? `${filePath}:${line}` : filePath);

  if (!supportsHyperlinks()) {
    return text;
  }

  // Resolve to absolute path for the file:// URL
  const absolute = path.isAbsolute(filePath)
    ? filePath
    : repoRoot
      ? path.resolve(repoRoot, filePath)
      : path.resolve(filePath);

  let url = pathToFileURL(absolute).href;
  if (line != null) {
    url += `#L${line}`;
  }

  return `${OSC8_START}${url}${OSC8_END}${text}${OSC8_START}${OSC8_END}`;
}

/**
 * Wrap text in an OSC 8 hyperlink to an arbitrary URL.
 */
export function urlLink(url: string, displayText?: string): string {
  const text = displayText ?? url;
  if (!supportsHyperlinks()) return text;
  return `${OSC8_START}${url}${OSC8_END}${text}${OSC8_START}${OSC8_END}`;
}
