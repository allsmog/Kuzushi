/**
 * Scenario barrel — each `*.ts` here imports for side-effect registration
 * via `registerScenario(...)`. Keep import order alphabetical so
 * `listScenarios()` output is stable.
 */
import "./actor-detail.js";
import "./catalog.js";
import "./finding.js";
import "./findings-empty.js";
import "./findings-many.js";
import "./module-run-active.js";
import "./module-run-done.js";
import "./module-sast.js";
import "./prompts-editor.js";
import "./task-story.js";
import "./threats-dfd.js";
import "./threats-scope.js";
import "./threats-stories.js";
import "./threats-stride.js";
import "./threats-summary.js";
import "./tune.js";
