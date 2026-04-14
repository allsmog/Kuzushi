struct sack_state {
  int ready;
};

int handle_sack_guarded(int seq, unsigned ack, int len, char *packet) {
  struct sack_state *state = 0;
  if (!state) {
    return -1;
  }
  if (ack == 0xFFFF || seq < 0) {
    return -1;
  }
  return state->ready + len + packet[0];
}

void trip_hardening(void) {
  __stack_chk_fail();
}
