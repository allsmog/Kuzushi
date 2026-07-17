import * as React from "react";
import { KeyHints, cx } from "./shared.js";
import type { PlanTask, PlanningCardProps, Tone } from "./types.js";

const DEFAULT_CONTROLS = [
  { key: "j/k", label: "move" },
  { key: "space", label: "toggle" },
  { key: "y", label: "apply active" },
  { key: "n", label: "discard" },
  { key: "/yes", label: "" },
  { key: "/no", label: "" },
] as const;

function taskMarker(task: PlanTask): string {
  const cursor = task.selected ? "> " : "  ";
  if (task.skipped) return `${cursor}[ ]`;
  switch (task.state) {
    case "done": return `${cursor}[✓]`;
    case "running": return `${cursor}[●]`;
    case "failed": return `${cursor}[!]`;
    case "blocked": return `${cursor}[×]`;
    default: return `${cursor}[x]`;
  }
}

function taskTone(task: PlanTask): Tone {
  if (task.skipped || task.state === "blocked") return "muted";
  if (task.state === "failed") return "danger";
  if (task.state === "running") return "accent";
  return "success";
}

export function PlanningCard({
  goal,
  tasks,
  state = "planning",
  summary,
  returned = false,
  controls = DEFAULT_CONTROLS,
}: PlanningCardProps): React.ReactElement {
  const activeCount = tasks.filter((task) => !task.skipped).length;
  return (
    <section className={cx("kz-planning-card", `kz-plan-${state}`, returned && "kz-plan-returned")}>
      <div className="kz-plan-title">◆ PLAN · goal: {goal} · {activeCount}/{tasks.length} active</div>
      {summary && <div className="kz-plan-summary">  summary: {summary}</div>}
      <div className="kz-plan-tasks">
        {tasks.map((task) => (
          <div className={cx("kz-plan-task", `kz-tone-${taskTone(task)}`)} key={task.id}>
            <span>{taskMarker(task)}</span> <span>{task.label}</span>
            {task.detail && <span className="kz-plan-detail"> · {task.detail}</span>}
          </div>
        ))}
      </div>
      <KeyHints hints={controls} />
    </section>
  );
}
