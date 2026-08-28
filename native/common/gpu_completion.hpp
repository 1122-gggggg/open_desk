#pragma once

#include <d3d11.h>
#include <windows.h>

#include <chrono>

namespace latencydesk {

// Sleep(1) on Windows is a 1–15.6 ms timer wait. Capture and decode completion
// queries typically retire in tens of microseconds; spinning then yielding the
// rest of the timeslice keeps the GPU pipeline moving without that floor.
inline HRESULT wait_for_gpu_query(ID3D11DeviceContext* context, ID3D11Query* query,
                                  std::chrono::milliseconds timeout) noexcept {
  if (context == nullptr || query == nullptr) {
    return E_POINTER;
  }
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  unsigned spins = 0;
  while (std::chrono::steady_clock::now() < deadline) {
    const HRESULT result =
        context->GetData(query, nullptr, 0, D3D11_ASYNC_GETDATA_DONOTFLUSH);
    if (result == S_OK) {
      return S_OK;
    }
    if (result != S_FALSE) {
      return result;
    }
    if (spins < 64) {
      YieldProcessor();
    } else {
      SwitchToThread();
      spins = 0;
    }
    ++spins;
  }
  return HRESULT_FROM_WIN32(WAIT_TIMEOUT);
}

}  // namespace latencydesk
