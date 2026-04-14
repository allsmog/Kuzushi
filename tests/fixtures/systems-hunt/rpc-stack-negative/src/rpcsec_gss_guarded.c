int handle_rpcsec_gss_guarded(unsigned int len, char *token) {
  char stack_buf[32];
  if (len > sizeof(stack_buf)) {
    return -1;
  }
  if (len > 0 && token[0] != 0) {
    memcpy(stack_buf, token, len);
  }
  return stack_buf[0];
}
