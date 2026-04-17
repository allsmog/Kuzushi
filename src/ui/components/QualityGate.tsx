/**
 * Quality gate result display with badge and tree-style violations.
 */

import { Box, Text } from "ink";
import type React from "react";
import type { QualityGateResult } from "../../quality-gate.js";
import { badge } from "../format.js";
import { icons } from "../icons.js";
import { tokens } from "../tokens.js";

interface QualityGateProps {
  result: QualityGateResult;
}

export function QualityGate({ result }: QualityGateProps): React.ReactElement {
  return (
    <Box flexDirection="column" paddingLeft={2}>
      <Text>{""}</Text>
      {result.passed ? (
        <Text>
          {badge("PASSED", "green")} {tokens.label("Quality Gates")}
        </Text>
      ) : (
        <>
          <Text>
            {badge("FAILED", "red")} {tokens.label("Quality Gates")}
          </Text>
          {result.violations.map((violation, i) => {
            const isLast = i === result.violations.length - 1;
            const connector = isLast ? icons.treeLast : icons.treeMiddle;
            return (
              <Box key={i} flexDirection="column">
                <Text>
                  {tokens.muted(connector)} {tokens.danger(icons.error)}{" "}
                  {tokens.label(violation.rule)}: {violation.message}
                </Text>
                {violation.fingerprints && violation.fingerprints.length > 0 && (
                  <>
                    {violation.fingerprints.slice(0, 5).map((fp, fi) => (
                      <Text key={fi}>
                        {isLast ? "  " : tokens.muted(icons.treePipe)} {"  "}
                        {tokens.muted(fp.slice(0, 16))}...
                      </Text>
                    ))}
                    {violation.fingerprints.length > 5 && (
                      <Text>
                        {isLast ? "  " : tokens.muted(icons.treePipe)} {"  "}
                        {tokens.muted(`... and ${violation.fingerprints.length - 5} more`)}
                      </Text>
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
