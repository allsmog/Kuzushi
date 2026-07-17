import * as React from "react";
import { KeyHints, PHASE_META, cx, toneClass } from "./shared.js";
import { TerminalFrame } from "./TerminalFrame.js";
import type { RunFocusProps, RunState, RunTask, Tone } from "./types.js";

function runTone(state: RunState): Tone {
  if (state === "completed") return "success";
  if (state === "failed") return "danger";
  if (state === "live") return "success";
  return "warn";
}

function runLabel(state: RunState): string {
  switch (state) {
    case "live": return "● LIVE";
    case "completed": return "✓ COMPLETED";
    case "partial": return "⚠ PARTIAL";
    case "failed": return "✗ FAILED";
    case "canceled": return "× CANCELED";
    case "interrupted": return "× INTERRUPTED";
  }
}

function taskGlyph(task: RunTask): string {
  switch (task.state) {
    case "done": return "✓";
    case "running": return "●";
    case "failed": return "!";
    case "blocked": return "▣";
    case "skipped": return "⊘";
    default: return "·";
  }
}

function taskTone(task: RunTask): Tone {
  if (task.state === "done") return "success";
  if (task.state === "running") return "accent";
  if (task.state === "failed") return "danger";
  if (task.state === "blocked") return "warn";
  return "muted";
}

export function RunFocus({
  phase,
  runId,
  state,
  context,
  health,
  tasks,
  output,
  currentTask,
  focus = "tasks",
  controls,
  cols = 80,
  rows = 24,
}: RunFocusProps): React.ReactElement {
  const layout = cols < 50 || rows < 14 ? "focused" : cols < 78 ? "stacked" : "side-by-side";
  const paneFocus = focus;
  const done = tasks.filter((task) => task.state === "done").length;
  const running = tasks.filter((task) => task.state === "running").length;
  const defaultControls = state === "live"
    ? [
        { key: "j/k/g/G", label: "scroll" },
        { key: "Tab", label: "pane" },
        { key: "V", label: "verbose" },
        { key: "Space", label: "pause" },
        { key: "x", label: "reset view" },
        { key: "Enter", label: "focus" },
        { key: "b", label: "background" },
        { key: "s", label: "steer" },
      ]
    : [{ key: "Enter", label: "return" }, { key: "t", label: "trace" }, { key: "Esc", label: "close" }];
  return (
    <TerminalFrame title="kuzushi · run focus" cols={cols} rows={rows} chromeless>
      <div className={cx("kz-screen", "kz-run-focus", `kz-run-${layout}`)}>
        <header className="kz-run-header">
          <div className="kz-run-title">
            RUN FOCUS{phase && <><span> · </span><span className={toneClass(phase)}>{PHASE_META[phase].label}</span></>} · run {runId} · {done}/{tasks.length} done · {running} running
          </div>
          <div className="kz-context-line">{context}</div>
          <div className={cx("kz-health-line", toneClass(runTone(state)))}>{runLabel(state)} · {health}</div>
        </header>
        <main className="kz-run-panes">
          {(layout !== "focused" || paneFocus === "tasks") && <section className={cx("kz-run-tasks", paneFocus === "tasks" && "kz-run-pane-focused")}>
            <div className="kz-pane-title">{paneFocus === "tasks" && <span>▸ </span>}── TASKS ──</div>
            {tasks.map((task) => (
              <div className={cx("kz-task-row", toneClass(taskTone(task)), task.id === currentTask && "kz-selected")} key={task.id}>
                {task.id === currentTask && <span>▸ </span>}<span>{taskGlyph(task)}</span> <span>{task.label}</span>{task.detail && <span className="kz-task-detail"> · {task.detail}</span>}
              </div>
            ))}
          </section>}
          {(layout !== "focused" || paneFocus === "output") && <section className={cx("kz-run-output", paneFocus === "output" && "kz-run-pane-focused")}>
            <div className="kz-pane-title">{paneFocus === "output" && <span>▸ </span>}── OUTPUT ──</div>
            {output.map((line, index) => (
              <div className={cx("kz-output-row", toneClass(line.tone))} key={index}>
                {line.source && <span className="kz-output-source">[{line.source}] </span>}{line.text}
              </div>
            ))}
          </section>}
        </main>
        <footer className="kz-run-footer">
          <div className="kz-run-authority">{state === "live" ? `current ${currentTask ?? "run"}` : `${state} · durable run ${runId}`}</div>
          <KeyHints hints={controls ?? defaultControls} />
        </footer>
      </div>
    </TerminalFrame>
  );
}
