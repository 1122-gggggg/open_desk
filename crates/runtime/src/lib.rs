//! Secure runtime composition boundary for native LatencyDesk roles.
//!
//! Concrete Host and Client orchestration is introduced after the authenticated
//! protocol and session authority are available.
//!
//! ```compile_fail
//! use latencydesk_socket_transport::SecureSessionRuntime;
//! let _ = SecureSessionRuntime::new();
//! ```
