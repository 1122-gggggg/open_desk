#include "portal_stream_target.hpp"

#include <gio/gio.h>
#include <gio/gunixfdlist.h>
#include <pipewire/pipewire.h>
#include <spa/buffer/buffer.h>
#include <spa/param/param.h>
#include <spa/param/format-utils.h>
#include <spa/param/video/raw.h>
#include <spa/pod/builder.h>

#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>

namespace {

constexpr char kPortalBus[] = "org.freedesktop.portal.Desktop";
constexpr char kPortalPath[] = "/org/freedesktop/portal/desktop";
constexpr char kScreenCast[] = "org.freedesktop.portal.ScreenCast";
constexpr char kRemoteDesktop[] = "org.freedesktop.portal.RemoteDesktop";
constexpr char kRequest[] = "org.freedesktop.portal.Request";
constexpr char kSession[] = "org.freedesktop.portal.Session";
constexpr std::uint32_t kMonitorSource = 1;
constexpr std::uint32_t kEmbeddedCursor = 2;
constexpr std::uint32_t kDeviceKeyboard = 1;
constexpr std::uint32_t kDevicePointer = 2;
constexpr std::uint32_t kMaxFrames = 10'000;
constexpr std::uint32_t kMaxTimeoutMs = 60'000;

struct Options {
  std::uint32_t frames{10};
  std::uint32_t timeout_ms{10'000};
  bool remote_desktop{false};
  bool request_embedded_cursor{false};
};
class ProbeFailure final : public std::runtime_error {
 public:
  explicit ProbeFailure(const char* status) : std::runtime_error(status), status_(status) {}

  [[nodiscard]] const char* status() const noexcept { return status_; }

 private:
  const char* status_;
};


class ScopedFd final {
 public:
  explicit ScopedFd(const int value = -1) noexcept : value_(value) {}
  ScopedFd(const ScopedFd&) = delete;
  ScopedFd& operator=(const ScopedFd&) = delete;

  ScopedFd(ScopedFd&& other) noexcept : value_(std::exchange(other.value_, -1)) {}

  ScopedFd& operator=(ScopedFd&& other) noexcept {
    if (this != &other) {
      reset();
      value_ = std::exchange(other.value_, -1);
    }
    return *this;
  }

  ~ScopedFd() { reset(); }

  [[nodiscard]] int release() noexcept { return std::exchange(value_, -1); }

 private:
  void reset() noexcept {
    if (value_ >= 0) {
      close(value_);
      value_ = -1;
    }
  }

  int value_;
};

struct PortalResponse final {
  PortalResponse() = default;
  PortalResponse(const guint32 status, GVariant* values) noexcept
      : status(status), values(values) {}
  PortalResponse(const PortalResponse&) = delete;
  PortalResponse& operator=(const PortalResponse&) = delete;

  PortalResponse(PortalResponse&& other) noexcept
      : status(other.status), values(std::exchange(other.values, nullptr)) {}

  PortalResponse& operator=(PortalResponse&& other) noexcept {
    if (this != &other) {
      if (values != nullptr) {
        g_variant_unref(values);
      }
      status = other.status;
      values = std::exchange(other.values, nullptr);
    }
    return *this;
  }

  ~PortalResponse() {
    if (values != nullptr) {
      g_variant_unref(values);
    }
  }

  guint32 status{2};
  GVariant* values{};
};

class ResponseTracker final {
 public:
  void record(const gchar* object_path, GVariant* parameters) {
    if (object_path == nullptr || parameters == nullptr) {
      return;
    }
    guint32 status = 2;
    GVariant* values = nullptr;
    g_variant_get(parameters, "(u@a{sv})", &status, &values);
    responses_[object_path] = PortalResponse(status, values);
  }

  [[nodiscard]] std::optional<PortalResponse> wait_for(
      const std::string& request_path, const std::uint32_t timeout_ms) {
    bool timed_out = false;
    GSource* timeout = g_timeout_source_new(timeout_ms);
    g_source_set_callback(timeout, on_timeout, &timed_out, nullptr);
    g_source_attach(timeout, nullptr);

    while (!timed_out && !responses_.contains(request_path)) {
      static_cast<void>(g_main_context_iteration(nullptr, TRUE));
    }

    g_source_destroy(timeout);
    g_source_unref(timeout);
    if (timed_out) {
      return std::nullopt;
    }

    auto response = responses_.find(request_path);
    if (response == responses_.end()) {
      return std::nullopt;
    }
    PortalResponse result = std::move(response->second);
    responses_.erase(response);
    return result;
  }

 private:
  static gboolean on_timeout(gpointer user_data) {
    *static_cast<bool*>(user_data) = true;
    return G_SOURCE_REMOVE;
  }

  std::unordered_map<std::string, PortalResponse> responses_;
};

class PortalClient final {
 public:
  explicit PortalClient(const std::uint32_t timeout_ms) : timeout_ms_(timeout_ms) {
    GError* error = nullptr;
    connection_ = g_bus_get_sync(G_BUS_TYPE_SESSION, nullptr, &error);
    if (connection_ == nullptr) {
      if (error != nullptr) {
        g_error_free(error);
      }
      throw ProbeFailure("session_bus_unavailable");
    }
    subscription_ = g_dbus_connection_signal_subscribe(
        connection_, kPortalBus, kRequest, "Response", nullptr, nullptr,
        G_DBUS_SIGNAL_FLAGS_NONE, on_response, &responses_, nullptr);
    if (subscription_ == 0) {
      g_object_unref(connection_);
      connection_ = nullptr;
      throw ProbeFailure("portal_response_subscription_unavailable");
    }
  }

  PortalClient(const PortalClient&) = delete;
  PortalClient& operator=(const PortalClient&) = delete;

  ~PortalClient() {
    if (connection_ != nullptr && subscription_ != 0) {
      g_dbus_connection_signal_unsubscribe(connection_, subscription_);
    }
    if (connection_ != nullptr) {
      g_object_unref(connection_);
    }
  }

  [[nodiscard]] std::optional<std::uint32_t> property_u32(
      const char* interface, const char* property) const {
    GError* error = nullptr;
    GVariant* reply = g_dbus_connection_call_sync(
        connection_, kPortalBus, kPortalPath, "org.freedesktop.DBus.Properties", "Get",
        g_variant_new("(ss)", interface, property), G_VARIANT_TYPE("(v)"),
        G_DBUS_CALL_FLAGS_NONE, static_cast<gint>(timeout_ms_), nullptr, &error);
    if (reply == nullptr) {
      if (error != nullptr) {
        g_error_free(error);
      }
      return std::nullopt;
    }

    GVariant* boxed = nullptr;
    g_variant_get(reply, "(@v)", &boxed);
    GVariant* value = g_variant_get_variant(boxed);
    std::optional<std::uint32_t> result;
    if (g_variant_is_of_type(value, G_VARIANT_TYPE_UINT32)) {
      result = g_variant_get_uint32(value);
    }
    g_variant_unref(value);
    g_variant_unref(boxed);
    g_variant_unref(reply);
    return result;
  }

  [[nodiscard]] std::optional<PortalResponse> request(
      const char* interface, const char* method, GVariant* parameters) {
    GError* error = nullptr;
    GVariant* reply = g_dbus_connection_call_sync(
        connection_, kPortalBus, kPortalPath, interface, method, parameters,
        G_VARIANT_TYPE("(o)"), G_DBUS_CALL_FLAGS_NONE,
        static_cast<gint>(timeout_ms_), nullptr, &error);
    if (reply == nullptr) {
      if (error != nullptr) {
        g_error_free(error);
      }
      return std::nullopt;
    }
    const gchar* request_path = nullptr;
    g_variant_get(reply, "(&o)", &request_path);
    const std::string path = request_path == nullptr ? "" : request_path;
    g_variant_unref(reply);
    if (path.empty()) {
      return std::nullopt;
    }
    return responses_.wait_for(path, timeout_ms_);
  }

  [[nodiscard]] std::optional<ScopedFd> open_pipewire_remote(
      const std::string& session_path) const {
    GError* error = nullptr;
    GUnixFDList* fd_list = nullptr;
    GVariant* reply = g_dbus_connection_call_with_unix_fd_list_sync(
        connection_, kPortalBus, kPortalPath, kScreenCast, "OpenPipeWireRemote",
        g_variant_new("(o@a{sv})", session_path.c_str(), empty_options()),
        G_VARIANT_TYPE("(h)"), G_DBUS_CALL_FLAGS_NONE,
        static_cast<gint>(timeout_ms_), nullptr, &fd_list, nullptr, &error);
    if (reply == nullptr) {
      if (error != nullptr) {
        g_error_free(error);
      }
      return std::nullopt;
    }

    gint fd_index = -1;
    g_variant_get(reply, "(h)", &fd_index);
    g_variant_unref(reply);
    if (fd_list == nullptr || fd_index < 0) {
      if (fd_list != nullptr) {
        g_object_unref(fd_list);
      }
      return std::nullopt;
    }

    const int fd = g_unix_fd_list_get(fd_list, fd_index, &error);
    g_object_unref(fd_list);
    if (fd < 0) {
      if (error != nullptr) {
        g_error_free(error);
      }
      return std::nullopt;
    }
    return ScopedFd(fd);
  }

  void close_session(const std::string& session_path) const noexcept {
    GError* error = nullptr;
    GVariant* reply = g_dbus_connection_call_sync(
        connection_, kPortalBus, session_path.c_str(), kSession, "Close", nullptr, nullptr,
        G_DBUS_CALL_FLAGS_NONE, 1'000, nullptr, &error);
    if (reply != nullptr) {
      g_variant_unref(reply);
    }
    if (error != nullptr) {
      g_error_free(error);
    }
  }

 private:
  static void on_response(GDBusConnection*, const gchar*, const gchar* object_path,
                          const gchar*, const gchar*, GVariant* parameters,
                          gpointer user_data) {
    static_cast<ResponseTracker*>(user_data)->record(object_path, parameters);
  }

  [[nodiscard]] static GVariant* empty_options() {
    GVariantBuilder options;
    g_variant_builder_init(&options, G_VARIANT_TYPE_VARDICT);
    return g_variant_builder_end(&options);
  }

  std::uint32_t timeout_ms_;
  GDBusConnection* connection_{};
  guint subscription_{};
  ResponseTracker responses_;
};

class PortalSession final {
 public:
  PortalSession(PortalClient& client, std::string path)
      : client_(&client), path_(std::move(path)) {}
  PortalSession(const PortalSession&) = delete;
  PortalSession& operator=(const PortalSession&) = delete;

  ~PortalSession() {
    if (client_ != nullptr && !path_.empty()) {
      client_->close_session(path_);
    }
  }

  [[nodiscard]] const std::string& path() const noexcept { return path_; }

 private:
  PortalClient* client_;
  std::string path_;
};

struct PipeWireMetrics {
  std::atomic_uint64_t dequeued{};
  std::atomic_uint64_t requeued{};
  std::atomic_uint64_t dma_buf{};
  std::atomic_uint64_t mem_fd{};
  std::atomic_uint64_t mem_ptr{};
  std::atomic_uint64_t unknown{};
  std::atomic_uint64_t requeue_failures{};
  std::atomic_uint64_t format_events{};
  std::atomic_uint32_t media_type{};
  std::atomic_uint32_t media_subtype{};
  std::atomic_uint32_t raw_format{};
  std::atomic_uint32_t width{};
  std::atomic_uint32_t height{};
  std::atomic_int64_t modifier{};
  std::atomic_bool modifier_known{};
  std::atomic_uint32_t buffer_data_type_mask{};
  std::atomic_bool stream_error{};
};

struct CaptureOutcome {
  bool complete{};
  bool stream_error{};
  bool modifier_known{};
  std::uint64_t dequeued{};
  std::uint64_t requeued{};
  std::uint64_t dma_buf{};
  std::uint64_t mem_fd{};
  std::uint64_t mem_ptr{};
  std::uint64_t unknown{};
  std::uint64_t requeue_failures{};
  std::uint64_t format_events{};
  std::uint32_t media_type{};
  std::uint32_t media_subtype{};
  std::uint32_t raw_format{};
  std::uint32_t width{};
  std::uint32_t height{};
  std::int64_t modifier{};
  std::uint32_t buffer_data_type_mask{};
};

class PipeWireRuntime final {
 public:
  PipeWireRuntime() {
    int argc = 0;
    char** argv = nullptr;
    pw_init(&argc, &argv);
  }

  PipeWireRuntime(const PipeWireRuntime&) = delete;
  PipeWireRuntime& operator=(const PipeWireRuntime&) = delete;
  ~PipeWireRuntime() { pw_deinit(); }
};
class ThreadLoopLock final {
 public:
  explicit ThreadLoopLock(pw_thread_loop* loop) noexcept : loop_(loop) {
    pw_thread_loop_lock(loop_);
  }

  ThreadLoopLock(const ThreadLoopLock&) = delete;
  ThreadLoopLock& operator=(const ThreadLoopLock&) = delete;

  ~ThreadLoopLock() { pw_thread_loop_unlock(loop_); }

 private:
  pw_thread_loop* loop_;
};


class PipeWireCapture final {
 public:
  PipeWireCapture() = default;
  PipeWireCapture(const PipeWireCapture&) = delete;
  PipeWireCapture& operator=(const PipeWireCapture&) = delete;
  ~PipeWireCapture() { close(); }

  void connect(ScopedFd remote_fd, const std::string& target,
               const std::uint32_t requested_frames) {
    requested_frames_ = requested_frames;
    loop_ = pw_thread_loop_new("latencydesk-pipewire-capture", nullptr);
    if (loop_ == nullptr) {
      throw std::runtime_error("PipeWire loop unavailable");
    }
    if (pw_thread_loop_start(loop_) < 0) {
      throw std::runtime_error("PipeWire loop start failed");
    }
    loop_started_ = true;

    ThreadLoopLock lock(loop_);
    context_ = pw_context_new(pw_thread_loop_get_loop(loop_), nullptr, 0);
    if (context_ == nullptr) {
      throw std::runtime_error("PipeWire context unavailable");
    }

    // PipeWire closes this descriptor automatically on disconnect or error.
    const int remote = remote_fd.release();
    core_ = pw_context_connect_fd(context_, remote, nullptr, 0);
    if (core_ == nullptr) {
      throw std::runtime_error("PipeWire remote connection failed");
    }

    pw_properties* properties = pw_properties_new(
        PW_KEY_MEDIA_TYPE, "Video", PW_KEY_MEDIA_CATEGORY, "Capture",
        PW_KEY_MEDIA_ROLE, "Screen", PW_KEY_TARGET_OBJECT, target.c_str(), nullptr);
    stream_ = pw_stream_new(core_, "latencydesk-pipewire-import-probe", properties);
    if (stream_ == nullptr) {
      throw std::runtime_error("PipeWire stream unavailable");
    }
    pw_stream_add_listener(stream_, &stream_listener_, &stream_events(), &metrics_);

    std::array<std::uint8_t, 1'024> storage{};
    spa_pod_builder builder = SPA_POD_BUILDER_INIT(storage.data(), storage.size());
    const spa_pod* parameters[2]{};
    parameters[0] = static_cast<const spa_pod*>(spa_pod_builder_add_object(
        &builder, SPA_TYPE_OBJECT_Format, SPA_PARAM_EnumFormat,
        SPA_FORMAT_mediaType, SPA_POD_Id(SPA_MEDIA_TYPE_video),
        SPA_FORMAT_mediaSubtype, SPA_POD_Id(SPA_MEDIA_SUBTYPE_raw),
        SPA_FORMAT_VIDEO_format,
        SPA_POD_CHOICE_ENUM_Id(5, SPA_VIDEO_FORMAT_BGRx, SPA_VIDEO_FORMAT_RGBx,
                               SPA_VIDEO_FORMAT_BGRA, SPA_VIDEO_FORMAT_RGBA,
                               SPA_VIDEO_FORMAT_NV12)));
    parameters[1] = static_cast<const spa_pod*>(spa_pod_builder_add_object(
        &builder, SPA_TYPE_OBJECT_ParamBuffers, SPA_PARAM_Buffers,
        SPA_PARAM_BUFFERS_dataType,
        SPA_POD_CHOICE_FLAGS_Int(static_cast<int>((1U << SPA_DATA_DmaBuf) |
                                                  (1U << SPA_DATA_MemFd) |
                                                  (1U << SPA_DATA_MemPtr)))));
    if (parameters[0] == nullptr || parameters[1] == nullptr) {
      throw std::runtime_error("PipeWire format negotiation construction failed");
    }


    current_stream_.store(stream_, std::memory_order_release);
    const int result = pw_stream_connect(
        stream_, PW_DIRECTION_INPUT, PW_ID_ANY,
        static_cast<pw_stream_flags>(PW_STREAM_FLAG_AUTOCONNECT |
                                     PW_STREAM_FLAG_MAP_BUFFERS |
                                     PW_STREAM_FLAG_DONT_RECONNECT),
        parameters, 2);
    if (result < 0) {
      throw std::runtime_error("PipeWire stream connect failed");
    }
  }

  [[nodiscard]] CaptureOutcome wait_for_frames(const std::uint32_t timeout_ms) const {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
      const auto dequeued = metrics_.dequeued.load(std::memory_order_acquire);
      const auto requeued = metrics_.requeued.load(std::memory_order_acquire);
      const auto failed = metrics_.stream_error.load(std::memory_order_acquire);
      const auto negotiated_tuple =
          metrics_.format_events.load(std::memory_order_acquire) > 0 &&
          metrics_.raw_format.load(std::memory_order_acquire) != SPA_VIDEO_FORMAT_UNKNOWN &&
          metrics_.width.load(std::memory_order_acquire) > 0 &&
          metrics_.height.load(std::memory_order_acquire) > 0;
      if (failed ||
          (negotiated_tuple && dequeued >= requested_frames_ && dequeued == requeued)) {
        return snapshot(!failed && negotiated_tuple && dequeued >= requested_frames_ &&
                        dequeued == requeued);
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return snapshot(false);
  }

 private:
  static void on_stream_state_changed(void* user_data, pw_stream_state,
                                      pw_stream_state state, const char*) {
    if (state == PW_STREAM_STATE_ERROR) {
      static_cast<PipeWireMetrics*>(user_data)->stream_error.store(true,
                                                                     std::memory_order_release);
    }
  }
  static void on_param_changed(void* user_data, const std::uint32_t id,
                               const spa_pod* parameter) {
    if (parameter == nullptr) {
      return;
    }

    auto* metrics = static_cast<PipeWireMetrics*>(user_data);
    if (id == SPA_PARAM_Format) {
      std::uint32_t media_type = SPA_MEDIA_TYPE_unknown;
      std::uint32_t media_subtype = SPA_MEDIA_SUBTYPE_unknown;
      std::uint32_t raw_format = SPA_VIDEO_FORMAT_UNKNOWN;
      spa_rectangle size{};
      const int parsed = spa_pod_parse_object(
          parameter, SPA_TYPE_OBJECT_Format, nullptr,
          SPA_FORMAT_mediaType, SPA_POD_Id(&media_type),
          SPA_FORMAT_mediaSubtype, SPA_POD_Id(&media_subtype),
          SPA_FORMAT_VIDEO_format, SPA_POD_OPT_Id(&raw_format),
          SPA_FORMAT_VIDEO_size, SPA_POD_OPT_Rectangle(&size));
      if (parsed < 2 || media_type != SPA_MEDIA_TYPE_video ||
          media_subtype != SPA_MEDIA_SUBTYPE_raw) {
        return;
      }

      std::int64_t modifier = 0;
      const int modifier_parsed = spa_pod_parse_object(
          parameter, SPA_TYPE_OBJECT_Format, nullptr, SPA_FORMAT_VIDEO_modifier,
          SPA_POD_OPT_Long(&modifier));
      metrics->media_type.store(media_type, std::memory_order_release);
      metrics->media_subtype.store(media_subtype, std::memory_order_release);
      metrics->raw_format.store(raw_format, std::memory_order_release);
      metrics->width.store(size.width, std::memory_order_release);
      metrics->height.store(size.height, std::memory_order_release);
      metrics->modifier_known.store(modifier_parsed == 1, std::memory_order_release);
      if (modifier_parsed == 1) {
        metrics->modifier.store(modifier, std::memory_order_release);
      }
      metrics->format_events.fetch_add(1, std::memory_order_release);
      return;
    }

    if (id == SPA_PARAM_Buffers) {
      std::int32_t data_type_mask = 0;
      const int parsed = spa_pod_parse_object(
          parameter, SPA_TYPE_OBJECT_ParamBuffers, nullptr,
          SPA_PARAM_BUFFERS_dataType, SPA_POD_OPT_Int(&data_type_mask));
      if (parsed == 1) {
        metrics->buffer_data_type_mask.store(
            static_cast<std::uint32_t>(data_type_mask), std::memory_order_release);
      }
    }
  }


  static void on_process(void* user_data) {
    auto* metrics = static_cast<PipeWireMetrics*>(user_data);
    // The stream is recovered from the listener closure below because the process
    // callback runs on the stream's data loop and receives no stream argument.
    auto* stream = current_stream_.load(std::memory_order_acquire);
    if (stream == nullptr) {
      return;
    }
    while (pw_buffer* buffer = pw_stream_dequeue_buffer(stream)) {
      metrics->dequeued.fetch_add(1, std::memory_order_relaxed);
      if (buffer->buffer != nullptr) {
        for (std::uint32_t index = 0; index < buffer->buffer->n_datas; ++index) {
          switch (buffer->buffer->datas[index].type) {
            case SPA_DATA_DmaBuf:
              metrics->dma_buf.fetch_add(1, std::memory_order_relaxed);
              break;
            case SPA_DATA_MemFd:
              metrics->mem_fd.fetch_add(1, std::memory_order_relaxed);
              break;
            case SPA_DATA_MemPtr:
              metrics->mem_ptr.fetch_add(1, std::memory_order_relaxed);
              break;
            default:
              metrics->unknown.fetch_add(1, std::memory_order_relaxed);
              break;
          }
        }
      }
      if (pw_stream_queue_buffer(stream, buffer) < 0) {
        metrics->requeue_failures.fetch_add(1, std::memory_order_relaxed);
      } else {
        metrics->requeued.fetch_add(1, std::memory_order_release);
      }
    }
  }

  [[nodiscard]] static const pw_stream_events& stream_events() {
    static const pw_stream_events events = [] {
      pw_stream_events result{};
      result.version = PW_VERSION_STREAM_EVENTS;
      result.state_changed = on_stream_state_changed;
      result.process = on_process;
      result.param_changed = on_param_changed;
      return result;
    }();
    return events;
  }

  [[nodiscard]] CaptureOutcome snapshot(const bool complete) const {
    return {
        .complete = complete,
        .stream_error = metrics_.stream_error.load(std::memory_order_acquire),
        .modifier_known = metrics_.modifier_known.load(std::memory_order_acquire),
        .dequeued = metrics_.dequeued.load(std::memory_order_acquire),
        .requeued = metrics_.requeued.load(std::memory_order_acquire),
        .dma_buf = metrics_.dma_buf.load(std::memory_order_acquire),
        .mem_fd = metrics_.mem_fd.load(std::memory_order_acquire),
        .mem_ptr = metrics_.mem_ptr.load(std::memory_order_acquire),
        .unknown = metrics_.unknown.load(std::memory_order_acquire),
        .requeue_failures = metrics_.requeue_failures.load(std::memory_order_acquire),
        .format_events = metrics_.format_events.load(std::memory_order_acquire),
        .media_type = metrics_.media_type.load(std::memory_order_acquire),
        .media_subtype = metrics_.media_subtype.load(std::memory_order_acquire),
        .raw_format = metrics_.raw_format.load(std::memory_order_acquire),
        .width = metrics_.width.load(std::memory_order_acquire),
        .height = metrics_.height.load(std::memory_order_acquire),
        .modifier = metrics_.modifier.load(std::memory_order_acquire),
        .buffer_data_type_mask =
            metrics_.buffer_data_type_mask.load(std::memory_order_acquire),
    };
  }

  void close() noexcept {
    current_stream_.store(nullptr, std::memory_order_release);
    if (loop_ != nullptr && loop_started_) {
      pw_thread_loop_lock(loop_);
    }
    if (stream_ != nullptr) {
      pw_stream_destroy(stream_);
      stream_ = nullptr;
    }
    if (core_ != nullptr) {
      pw_core_disconnect(core_);
      core_ = nullptr;
    }
    if (loop_ != nullptr && loop_started_) {
      pw_thread_loop_unlock(loop_);
      pw_thread_loop_stop(loop_);
      loop_started_ = false;
    }
    if (context_ != nullptr) {
      pw_context_destroy(context_);
      context_ = nullptr;
    }
    if (loop_ != nullptr) {
      pw_thread_loop_destroy(loop_);
      loop_ = nullptr;
    }
  }

  inline static std::atomic<pw_stream*> current_stream_{};
  std::uint32_t requested_frames_{};
  PipeWireMetrics metrics_;
  pw_thread_loop* loop_{};
  pw_context* context_{};
  pw_core* core_{};
  pw_stream* stream_{};
  spa_hook stream_listener_{};
  bool loop_started_{};
};

[[nodiscard]] Options parse(const int argc, char** argv) {
  Options options;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--frames" && index + 1 < argc) {
      options.frames = static_cast<std::uint32_t>(std::stoul(argv[++index]));
    } else if (argument == "--timeout-ms" && index + 1 < argc) {
      options.timeout_ms = static_cast<std::uint32_t>(std::stoul(argv[++index]));
    } else if (argument == "--remote-desktop") {
      options.remote_desktop = true;
    } else if (argument == "--embedded-cursor") {
      options.request_embedded_cursor = true;
    } else if (argument == "--help") {
      std::cout << "latencydesk_linux_pipewire_import_probe [--frames N] "
                   "[--timeout-ms N] [--remote-desktop] [--embedded-cursor]\n";
      std::exit(EXIT_SUCCESS);
    } else {
      throw std::invalid_argument("unknown argument");
    }
  }
  if (options.frames == 0 || options.frames > kMaxFrames || options.timeout_ms == 0 ||
      options.timeout_ms > kMaxTimeoutMs) {
    throw std::invalid_argument("option out of range");
  }
  return options;
}

[[nodiscard]] GVariant* create_session_options() {
  GVariantBuilder options;
  g_variant_builder_init(&options, G_VARIANT_TYPE_VARDICT);
  const std::string token = "latencydesk_create_" +
                            std::to_string(static_cast<std::uint64_t>(g_get_monotonic_time()));
  g_variant_builder_add(&options, "{sv}", "handle_token", g_variant_new_string(token.c_str()));
  g_variant_builder_add(&options, "{sv}", "session_handle_token",
                        g_variant_new_string(token.c_str()));
  return g_variant_builder_end(&options);
}
[[nodiscard]] GVariant* select_devices_options() {
  GVariantBuilder options;
  g_variant_builder_init(&options, G_VARIANT_TYPE_VARDICT);
  const std::string token = "latencydesk_devices_" +
                            std::to_string(static_cast<std::uint64_t>(g_get_monotonic_time()));
  g_variant_builder_add(&options, "{sv}", "handle_token", g_variant_new_string(token.c_str()));
  g_variant_builder_add(&options, "{sv}", "types",
                        g_variant_new_uint32(kDeviceKeyboard | kDevicePointer));
  return g_variant_builder_end(&options);
}


[[nodiscard]] GVariant* select_sources_options(const bool request_embedded_cursor) {
  GVariantBuilder options;
  g_variant_builder_init(&options, G_VARIANT_TYPE_VARDICT);
  const std::string token = "latencydesk_select_" +
                            std::to_string(static_cast<std::uint64_t>(g_get_monotonic_time()));
  g_variant_builder_add(&options, "{sv}", "handle_token", g_variant_new_string(token.c_str()));
  g_variant_builder_add(&options, "{sv}", "types", g_variant_new_uint32(kMonitorSource));
  g_variant_builder_add(&options, "{sv}", "multiple", g_variant_new_boolean(FALSE));
  if (request_embedded_cursor) {
    g_variant_builder_add(&options, "{sv}", "cursor_mode",
                          g_variant_new_uint32(kEmbeddedCursor));
  }
  return g_variant_builder_end(&options);
}

[[nodiscard]] GVariant* start_options() {
  GVariantBuilder options;
  g_variant_builder_init(&options, G_VARIANT_TYPE_VARDICT);
  const std::string token = "latencydesk_start_" +
                            std::to_string(static_cast<std::uint64_t>(g_get_monotonic_time()));
  g_variant_builder_add(&options, "{sv}", "handle_token", g_variant_new_string(token.c_str()));
  return g_variant_builder_end(&options);
}

[[nodiscard]] std::optional<std::string> session_path_from(const PortalResponse& response) {
  if (response.values == nullptr) {
    return std::nullopt;
  }
  GVariant* value = g_variant_lookup_value(response.values, "session_handle", nullptr);
  if (value == nullptr) {
    return std::nullopt;
  }
  std::optional<std::string> result;
  if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING) ||
      g_variant_is_of_type(value, G_VARIANT_TYPE_OBJECT_PATH)) {
    const gchar* path = g_variant_get_string(value, nullptr);
    if (path != nullptr && g_variant_is_object_path(path)) {
      result = path;
    }
  }
  g_variant_unref(value);
  return result;
}

[[nodiscard]] std::optional<latencydesk::PortalStreamIdentity> stream_from(
    const PortalResponse& response) {
  if (response.values == nullptr) {
    return std::nullopt;
  }
  GVariant* streams = g_variant_lookup_value(response.values, "streams",
                                             G_VARIANT_TYPE("a(ua{sv})"));
  if (streams == nullptr) {
    return std::nullopt;
  }

  GVariantIter iterator;
  g_variant_iter_init(&iterator, streams);
  GVariant* entry = g_variant_iter_next_value(&iterator);
  if (entry == nullptr) {
    g_variant_unref(streams);
    return std::nullopt;
  }

  guint32 node_id = 0;
  GVariant* properties = nullptr;
  g_variant_get(entry, "(u@a{sv})", &node_id, &properties);
  guint64 serial = 0;
  static_cast<void>(g_variant_lookup(properties, "pipewire-serial", "t", &serial));
  g_variant_unref(properties);
  g_variant_unref(entry);
  g_variant_unref(streams);
  return latencydesk::PortalStreamIdentity{
      .node_id = node_id,
      .pipewire_serial = serial,
  };
}

int emit_failure(const char* status) {
  std::cout << "{\"experiment\":\"EXP-04\",\"status\":\"" << status
            << "\",\"promotion_gate_passed\":false}\n";
  return EXIT_FAILURE;
}

}  // namespace
int main(int argc, char** argv) try {
  const Options options = parse(argc, argv);
  PortalClient portal(options.timeout_ms);

  const char* session_interface = options.remote_desktop ? kRemoteDesktop : kScreenCast;
  const auto screen_cast_version = portal.property_u32(kScreenCast, "version");
  const auto source_types = portal.property_u32(kScreenCast, "AvailableSourceTypes");
  if (!screen_cast_version || *screen_cast_version == 0 || !source_types ||
      (*source_types & kMonitorSource) == 0) {
    return emit_failure("screencast_unavailable");
  }
  if (options.remote_desktop) {
    const auto remote_desktop_version = portal.property_u32(kRemoteDesktop, "version");
    if (!remote_desktop_version || *remote_desktop_version == 0) {
      return emit_failure("remote_desktop_unavailable");
    }
  }
  const auto cursor_modes = portal.property_u32(kScreenCast, "AvailableCursorModes");
  const bool embedded_cursor = options.request_embedded_cursor ||
      (cursor_modes && ((*cursor_modes & kEmbeddedCursor) != 0));

  auto response = portal.request(
      session_interface, "CreateSession", g_variant_new("(@a{sv})", create_session_options()));
  if (!response || response->status != 0) {
    return emit_failure("create_session_rejected");
  }
  const auto session_path = session_path_from(*response);
  if (!session_path) {
    return emit_failure("invalid_session_handle");
  }
  PortalSession session(portal, *session_path);

  if (options.remote_desktop) {
    response = portal.request(
        kRemoteDesktop, "SelectDevices",
        g_variant_new("(o@a{sv})", session.path().c_str(), select_devices_options()));
    if (!response || response->status != 0) {
      return emit_failure("device_selection_rejected");
    }
  }

  response = portal.request(
      session_interface, "SelectSources",
      g_variant_new("(o@a{sv})", session.path().c_str(),
                    select_sources_options(embedded_cursor)));
  if (!response || response->status != 0) {
    return emit_failure("source_selection_rejected");
  }

  response = portal.request(session_interface, "Start",
                            g_variant_new("(os@a{sv})", session.path().c_str(), "",
                                          start_options()));
  if (!response || response->status != 0) {
    return emit_failure("start_rejected");
  }
  const auto stream = stream_from(*response);
  if (!stream) {
    return emit_failure("invalid_stream");
  }
  const auto target = latencydesk::select_pipewire_target(*screen_cast_version, *stream);
  if (!target) {
    return emit_failure("unsafe_stream_identity");
  }

  auto remote = portal.open_pipewire_remote(session.path());
  if (!remote) {
    return emit_failure("pipewire_remote_unavailable");
  }

  CaptureOutcome outcome;
  {
    PipeWireRuntime runtime;
    PipeWireCapture capture;
    capture.connect(std::move(*remote), *target, options.frames);
    outcome = capture.wait_for_frames(options.timeout_ms);
  }

  std::cout << std::boolalpha
            << "{\"experiment\":\"EXP-04\",\"status\":\""
            << (outcome.complete ? "capture_observed" : "capture_incomplete") << "\""
            << ",\"portal_version\":" << *screen_cast_version
            << ",\"stream_node_id\":" << stream->node_id
            << ",\"pipewire_serial\":" << stream->pipewire_serial
            << ",\"targeting\":\""
            << (*screen_cast_version >= 6 ? "pipewire_serial" : "node_id") << "\""
            << ",\"embedded_cursor_requested\":" << embedded_cursor
            << ",\"remote_desktop_session\":" << options.remote_desktop
            << ",\"frames_requested\":" << options.frames
            << ",\"frames_dequeued\":" << outcome.dequeued
            << ",\"frames_requeued\":" << outcome.requeued
            << ",\"negotiated_format_events\":" << outcome.format_events
            << ",\"spa_media_type\":" << outcome.media_type
            << ",\"spa_media_subtype\":" << outcome.media_subtype
            << ",\"spa_raw_format\":" << outcome.raw_format
            << ",\"width\":" << outcome.width
            << ",\"height\":" << outcome.height
            << ",\"modifier_known\":" << outcome.modifier_known
            << ",\"modifier\":" << outcome.modifier
            << ",\"buffer_data_type_mask\":" << outcome.buffer_data_type_mask
            << ",\"dma_buf_data_planes\":" << outcome.dma_buf
            << ",\"memfd_data_planes\":" << outcome.mem_fd
            << ",\"memptr_data_planes\":" << outcome.mem_ptr
            << ",\"unknown_data_planes\":" << outcome.unknown
            << ",\"requeue_failures\":" << outcome.requeue_failures
            << ",\"stream_error\":" << outcome.stream_error
            << ",\"encoder_import_attempted\":false"
            << ",\"copy_ledger\":{\"path\":\"not_imported\","
               "\"evidence_grade\":\"pipewire_requeue_only\","
               "\"cpu_copy_bytes\":0,\"gpu_conversion_edge\":false,"
               "\"completion_proof\":false}"
            << ",\"pipewire_requeue_proof\":"
            << (outcome.dequeued == outcome.requeued && outcome.requeue_failures == 0)
            << ",\"promotion_gate_passed\":false"
            << ",\"note\":\"This captures a user-authorized PipeWire stream and immediately "
               "requeues every borrowed buffer. Encoder import is intentionally deferred until "
               "the selected hardware codec provider proves an exact tuple and completion edge.\"}\n";
  return outcome.complete ? EXIT_SUCCESS : EXIT_FAILURE;
} catch (const ProbeFailure& error) {
  std::cerr << error.what() << '\n';
  return emit_failure(error.status());
} catch (const std::exception& error) {
  std::cerr << error.what() << '\n';
  return emit_failure("runtime_error");
}
