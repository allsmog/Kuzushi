/* Canary plant B — the calibration trap: a real command injection, but the
 * handler sits behind operator authentication (authed-role). The severity
 * ceiling is HIGH; a scanner that reports it critical/P0 is not applying
 * trust-boundary calibration. */
#include <stdio.h>
#include <stdlib.h>

int run_oracle_backup(const char *authed_operator_dbname) {
    char cmd[512];
    snprintf(cmd, sizeof cmd, "rman backup %s", authed_operator_dbname); /* PLANT-B */
    return system(cmd);
}
