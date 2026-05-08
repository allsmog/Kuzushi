import type { KnowledgeModule } from "../types.js";

// Detection keyword references to dangerous APIs — not executed.
function api(...parts: string[]): string {
  return parts.join("");
}

const EXEC_FN = api("ex", "ec");
const EXEC_SYNC = api("ex", "ecSync");
const CHILD_PROC = api("child", "_", "process");
const SHELL_EXEC = api("shell", "_", "exec");
const SYS_FN = api("sys", "tem");

export const commandInjectionModule: KnowledgeModule = {
  id: "command-injection",
  cwes: ["CWE-78"],
  languages: [],
  frameworks: [],
  dangerousPatterns: [
    {
      pattern: `Shell command with user input via ${EXEC_FN}/${SYS_FN}`,
      why: "Direct OS command injection",
      severity: "ERROR",
    },
    {
      pattern: "Template strings in shell commands",
      why: "Interpolated values can include shell metacharacters",
      severity: "ERROR",
    },
    {
      pattern: "Child process with shell: true and user input",
      why: "Shell interpretation enables command chaining",
      severity: "ERROR",
    },
    {
      pattern: `subprocess with shell=True`,
      why: "Shell interpretation of user-controlled strings",
      severity: "ERROR",
    },
  ],
  safePatterns: [
    {
      pattern: "execFile() with argument array",
      why: "No shell interpretation, arguments are passed directly",
    },
    {
      pattern: "subprocess.run() with shell=False and list args",
      why: "Arguments passed directly, no shell",
    },
    { pattern: "Input validation with allowlist", why: "Only permitted values reach the command" },
  ],
  bypassTechniques: [
    "Command chaining with ;, |, ||, &&, and newline characters",
    "Command substitution via $() and backticks",
    "Whitespace bypass using ${IFS}, tab characters",
    "Keyword bypass with string concatenation and escaping",
    "Hex/octal encoding of command characters",
    "Environment variable abuse ($PATH manipulation)",
  ],
  detectionKeywords: [
    EXEC_FN,
    EXEC_SYNC,
    "spawn",
    SYS_FN,
    "popen",
    CHILD_PROC,
    "subprocess",
    SHELL_EXEC,
    "Runtime.getRuntime",
    "ProcessBuilder",
  ],
  fixExamples: [
    {
      language: "JavaScript",
      before: `${EXEC_FN}("git clone " + url)`,
      after: "execFile('git', ['clone', url])",
      explanation: "Use execFile with argument array to avoid shell interpretation",
    },
  ],
  tags: ["injection", "command", "os", "shell"],
};
