struct frame_ctx {
  int slices[1024];
};

int decode_h264_slice_guarded(struct frame_ctx *frame, unsigned short slice_count, int slice) {
  if (slice_count >= 1024 || slice_count == 0xFFFF) {
    return -1;
  }
  return frame->slices[slice_count] = slice;
}
