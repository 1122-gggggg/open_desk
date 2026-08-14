#include "capture_detach.hpp"

#include <cstdlib>
#include <iostream>

int main() {
  latencydesk::CaptureDetachState state;
  if (!state.release_permitted()) {
    std::cerr << "fresh lease was not releasable\n";
    return EXIT_FAILURE;
  }

  state.native_work_started();
  if (state.release_permitted()) {
    std::cerr << "lease became releasable before completion proof\n";
    return EXIT_FAILURE;
  }

  state.completion_proven();
  if (!state.release_permitted()) {
    std::cerr << "lease remained blocked after completion proof\n";
    return EXIT_FAILURE;
  }

  std::cout << "{\"release_blocked_while_gpu_work_is_unproven\":true,"
               "\"release_allowed_after_completion_proof\":true}\n";
  return EXIT_SUCCESS;
}
