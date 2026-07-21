/* Canary plant C: local-only info leak (expected: medium, uncapped). */
#include <stdio.h>

void dump_internal_metrics(FILE *world_readable_log) {
    extern const char *session_token_cache;
    /* Writes a session token into a world-readable log; needs a local uid
     * on the host to read it. */
    fprintf(world_readable_log, "token=%s\n", session_token_cache); /* PLANT-C */
}
