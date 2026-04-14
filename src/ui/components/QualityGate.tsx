/**
 * Quality gate result display with badge and tree-style violations.
 */
import React from "react";
import { Box, Text } from "ink";
import chalk from "chalk";
import { icons } from "../icons.js";
import { badge } from "../format.js";
import type { QualityGateResult } from "../../quality-gate.js";

interface QualityGateProps {
  result: QualityGateResult;
}

export function QualityGate({ result }: QualityGateProps): React.ReactElement {
  return (
    <Box flexDirection="column">
      <Text>{""}</Text>
      {result.passed ? (
        <Text>{"  "}{badge("PASSED", "green")} {chalk.bold("Quality Gates")}</Text>
      ) : (
        <>
          <Text>{"  "}{badge("FAILED", "red")} {chalk.bold("Quality Gates")}</Text>
          {result.violations.map((violation, i) => {
            const isLast = i === result.violations.length - 1;
            const connector = isLast ? icons.treeLast : icons.treeMiddle;
            return (
              <Box key={i} flexDirection="column">
                <Text>{"  "}{chalk.dim(connector)} {chalk.red(icons.error)} {chalk.bold(violation.rule)}: {violation.message}</Text>
                {violation.fingerprints && violation.fingerprints.length > 0 && (
                  <>
                    {violation.fingerprints.slice(0, 5).map((fp, fi) => (
                      <Text key={fi}>{"  "}{isLast ? "  " : chalk.dim(icons.treePipe)} {"  "}{chalk.dim(fp.slice(0, 16))}...</Text>
                    ))}
                    {violation.fingerprints.length > 5 && (
                      <Text>{"  "}{isLast ? "  " : chalk.dim(icons.treePipe)} {"  "}{chalk.dim(`... and ${violation.fingerprints.length - 5} more`)}</Text>
                    )}
                  </>
                )}
              </Box>
            );
          })}
        </>
      )}
    </Box>
  );
}
