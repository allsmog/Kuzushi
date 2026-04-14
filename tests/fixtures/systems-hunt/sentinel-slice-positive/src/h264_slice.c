struct frame_ctx {
  int slices[65536];
};

int decode_h264_slice(struct frame_ctx *frame, unsigned short slice_count, int slice) {
  if (slice_count == 0xFFFF) {
    return frame->slices[slice_count + 1] = slice;
  }
  return frame->slices[slice_count++] = slice;
}
