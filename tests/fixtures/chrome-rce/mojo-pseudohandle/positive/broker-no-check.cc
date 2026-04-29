// Positive fixture for chrome-rce-mojo-broker-pseudohandle-reject.
// Anchored to CVE-2025-2783 (Operation ForumTroll, March 2025).
//
// This file is shaped like the pre-fix Mojo broker code: it accepts a HANDLE
// from a remote (renderer) process and calls ::DuplicateHandle without first
// rejecting Win32 pseudo-handles. A renderer can pass (HANDLE)-2 (current
// thread) and the broker will duplicate ITS OWN thread handle into the
// renderer process, enabling a sandbox escape.

#include <windows.h>

namespace ipc {

class BrokerImpl {
 public:
  // Mojo IPC entry point — `renderer_handle` is renderer-supplied.
  bool OnDuplicateHandleRequest(HANDLE renderer_handle,
                                HANDLE target_process,
                                HANDLE* out_dup) {
    // BUG: No check that renderer_handle is not a Win32 pseudo-handle.
    return ::DuplicateHandle(GetCurrentProcess(), renderer_handle,
                             target_process, out_dup, 0, FALSE,
                             DUPLICATE_SAME_ACCESS);
  }
};

}  // namespace ipc
