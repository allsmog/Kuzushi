/**
 * Auto dark/light terminal theme detection.
 *
 * Uses OSC 11 to query the terminal's background color, then computes
 * luminance to determine if the terminal is light or dark.
 *
 * Inspired by CC's systemTheme.ts. Used to adapt colors so dim text
 * is still readable on light terminals.
 *
 * Usage:
 *   const theme = await detectTheme();  // "dark" | "light"
 *   const theme = detectThemeSync();    // immediate guess from env
 */

export type Theme = "dark" | "light";

let cachedTheme: Theme | null = null;

/**
 * Synchronous theme guess based on environment variables.
 * Falls back to "dark" if no signal is available.
 */
export function detectThemeSync(): Theme {
  if (cachedTheme) return cachedTheme;

  // COLORFGBG is set by some terminals: "fg;bg" where higher bg = light
  const colorfgbg = process.env["COLORFGBG"];
  if (colorfgbg) {
    const parts = colorfgbg.split(";");
    const bg = parseInt(parts[parts.length - 1] ?? "", 10);
    if (!isNaN(bg)) {
      // ANSI color 0-6 = dark, 7+ = light (7 = white in standard palette)
      cachedTheme = bg >= 7 ? "light" : "dark";
      return cachedTheme;
    }
  }

  // macOS Terminal.app sets TERM_PROGRAM_VERSION but defaults to light
  if (process.env["TERM_PROGRAM"] === "Apple_Terminal") {
    cachedTheme = "light";
    return cachedTheme;
  }

  cachedTheme = "dark";
  return cachedTheme;
}

/**
 * Async theme detection via OSC 11 (query terminal background color).
 *
 * Sends `\x1b]11;?\x07` to the terminal and parses the response.
 * Falls back to sync detection after a short timeout.
 */
export async function detectTheme(timeoutMs = 200): Promise<Theme> {
  if (cachedTheme) return cachedTheme;

  // Only works on TTY
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    return detectThemeSync();
  }

  try {
    const bgColor = await queryTerminalBackground(timeoutMs);
    if (bgColor) {
      const luminance = computeLuminance(bgColor);
      cachedTheme = luminance > 0.5 ? "light" : "dark";
      return cachedTheme;
    }
  } catch {
    // Terminal doesn't support OSC 11 — fall through
  }

  return detectThemeSync();
}

/** Get the current theme (cached). */
export function getTheme(): Theme {
  return cachedTheme ?? detectThemeSync();
}

/** Override the detected theme. */
export function setTheme(theme: Theme): void {
  cachedTheme = theme;
}

/**
 * Query terminal background via OSC 11.
 * Returns [r, g, b] normalized to 0-1, or null on timeout/error.
 */
function queryTerminalBackground(timeoutMs: number): Promise<[number, number, number] | null> {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;

    const cleanup = () => {
      clearTimeout(timer);
      stdin.removeListener("data", onData);
      if (wasRaw !== undefined) {
        try { stdin.setRawMode(wasRaw); } catch { /* ignore */ }
      }
    };

    const timer = setTimeout(() => {
      cleanup();
      resolve(null);
    }, timeoutMs);

    const onData = (data: Buffer) => {
      const str = data.toString();
      const parsed = parseOsc11Response(str);
      cleanup();
      resolve(parsed);
    };

    try {
      stdin.setRawMode(true);
      stdin.once("data", onData);
      // Send OSC 11 query: "what is your background color?"
      process.stdout.write("\x1b]11;?\x07");
    } catch {
      cleanup();
      resolve(null);
    }
  });
}

/**
 * Parse an OSC 11 response.
 *
 * Formats:
 * - `\x1b]11;rgb:RRRR/GGGG/BBBB\x07` (most terminals, 16-bit per channel)
 * - `\x1b]11;rgb:RR/GG/BB\x07` (some terminals, 8-bit per channel)
 * - `\x1b]11;#RRGGBB\x07` (rare)
 */
function parseOsc11Response(response: string): [number, number, number] | null {
  // rgb:RRRR/GGGG/BBBB format
  const rgbMatch = response.match(/rgb:([0-9a-fA-F]+)\/([0-9a-fA-F]+)\/([0-9a-fA-F]+)/);
  if (rgbMatch) {
    const [, r, g, b] = rgbMatch;
    // Normalize to 0-1 based on hex string length (4 hex = 16 bit, 2 hex = 8 bit)
    const maxVal = r!.length === 4 ? 0xFFFF : r!.length === 2 ? 0xFF : 0xFFFF;
    return [
      parseInt(r!, 16) / maxVal,
      parseInt(g!, 16) / maxVal,
      parseInt(b!, 16) / maxVal,
    ];
  }

  // #RRGGBB format
  const hexMatch = response.match(/#([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{2})/);
  if (hexMatch) {
    const [, r, g, b] = hexMatch;
    return [
      parseInt(r!, 16) / 255,
      parseInt(g!, 16) / 255,
      parseInt(b!, 16) / 255,
    ];
  }

  return null;
}

/**
 * Compute relative luminance using ITU-R BT.709 coefficients.
 * Same formula CC uses for theme detection.
 */
function computeLuminance([r, g, b]: [number, number, number]): number {
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
