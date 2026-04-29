// Negative fixture for chrome-rce-mojo-broker-pseudohandle-reject.
// Anchored to CVE-2025-2783.
//
// The patched/safe shape: the broker explicitly rejects Win32 pseudo-handles
// (the closed enum -1..-6) before calling ::DuplicateHandle. The rule should
// NOT fire here.

#include <cstdint>
#include <windows.h>

namespace ipc {

// Reject the closed enum of Win32 pseudo-handles:
//   INVALID_HANDLE_VALUE (-1), GetCurrentProcess() (-1),
//   GetCurrentThread() (-2), GetCurrentProcessToken() (-3),
//   GetCurrentThreadToken() (-4), GetCurrentThreadEffectiveToken() (-5/-6).
inline bool IsPseudoHandle(HANDLE h) {
  const intptr_t v = reinterpret_cast<intptr_t>(h);
  return v <= 0 && v >= -6;
}

class BrokerImpl {
 public:
  bool OnDuplicateHandleRequest(HANDLE renderer_handle,
                                HANDLE target_process,
                                HANDLE* out_dup) {
    if (IsPseudoHandle(renderer_handle)) {
      return false;
    }
    return ::DuplicateHandle(GetCurrentProcess(), renderer_handle,
                             target_process, out_dup, 0, FALSE,
                             DUPLICATE_SAME_ACCESS);
  }
};

}  // namespace ipc
