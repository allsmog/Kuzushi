struct sack_state {
  int ready;
};

int handle_sack(int seq, unsigned ack, int len, char *packet) {
  struct sack_state *state = 0;
  if (ack == 0xFFFF && seq < (int)ack) {
    return state->ready + len + packet[0];
  }
  return 0;
}

void trip_hardening(void) {
  __stack_chk_fail();
}
