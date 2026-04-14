pub struct Descriptor {
  pub guest_len: usize,
  pub ptr: *mut u8,
}

pub unsafe fn map_guest(desc: &Descriptor) {
  if desc.guest_len > 4096 {
    return;
  }
  let slice = std::slice::from_raw_parts_mut(desc.ptr, desc.guest_len);
  slice[0] = 1;
}
