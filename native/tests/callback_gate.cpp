#include "callback_gate.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

namespace {

bool wait_for(const std::atomic<bool>& value) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
  while (!value.load(std::memory_order_acquire)) {
    if (std::chrono::steady_clock::now() >= deadline) return false;
    std::this_thread::yield();
  }
  return true;
}

}  // namespace

int main() {
  latencydesk::CallbackGate gate;
  std::atomic<bool> callback_entered{false};
  std::atomic<bool> release_callback{false};
  std::atomic<bool> drain_finished{false};

  std::thread callback([&] {
    auto lease = gate.try_enter();
    if (!lease) std::abort();
    callback_entered.store(true, std::memory_order_release);
    while (!release_callback.load(std::memory_order_acquire)) {
      std::this_thread::yield();
    }
  });
  if (!wait_for(callback_entered)) {
    release_callback.store(true, std::memory_order_release);
    callback.join();
    std::cerr << "callback did not enter\n";
    return EXIT_FAILURE;
  }

  std::thread shutdown([&] { gate.close(); });
  shutdown.join();
  if (gate.try_enter().has_value()) {
    release_callback.store(true, std::memory_order_release);
    callback.join();
    std::cerr << "callback entered after close\n";
    return EXIT_FAILURE;
  }

  std::thread drain([&] {
    gate.wait_for_drain();
    drain_finished.store(true, std::memory_order_release);
  });
  std::this_thread::yield();
  if (drain_finished.load(std::memory_order_acquire)) {
    release_callback.store(true, std::memory_order_release);
    callback.join();
    drain.join();
    std::cerr << "drain returned while callback lease was active\n";
    return EXIT_FAILURE;
  }

  release_callback.store(true, std::memory_order_release);
  if (!wait_for(drain_finished)) {
    std::cerr << "drain did not complete\n";
    std::abort();
  }
  callback.join();
  drain.join();

  std::cout << "{\"callback_rejected_after_close\":true,\"drain_waited_for_active_callback\":true}\n";
  return EXIT_SUCCESS;
}
