/* Canary plant A: pre-auth network OOB write (expected: critical, uncapped).
 * The length field comes straight off the wire and indexes a fixed buffer. */
#include <string.h>

char snapshot_buf[256];

int handle_snapshot_frame(const unsigned char *frame, unsigned int frame_len) {
    unsigned int payload_len = frame[0] | (frame[1] << 8);
    /* No listener auth, no bound check against sizeof(snapshot_buf): a
     * remote frame with payload_len > 256 writes past the buffer. */
    memcpy(snapshot_buf, frame + 2, payload_len); /* PLANT-A */
    return (int)payload_len;
}
