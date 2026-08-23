use std::env;

fn main() {
    for path in [
        "src/native.rs",
        "../../native/windows/include/latencydesk_windows_bridge.h",
        "../../native/windows/latencydesk_windows_bridge.cpp",
        "../../native/windows/input_event_queue.hpp",
        "../../native/windows/dda_capture_source.hpp",
        "../../native/windows/dda_capture_source.cpp",
        "../../native/windows/mf_h264_encoder.hpp",
        "../../native/windows/mf_h264_encoder.cpp",
        "../../native/common/capture_detach.hpp",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let mut build = cxx_build::bridge("src/native.rs");
    build
        .file("../../native/windows/latencydesk_windows_bridge.cpp")
        .file("../../native/windows/dda_capture_source.cpp")
        .file("../../native/windows/mf_h264_encoder.cpp")
        .include("../../native/windows/include")
        .include("../../native/windows")
        .include("../../native/common")
        .flag_if_supported("/std:c++20")
        .flag_if_supported("/EHsc")
        .compile("latencydesk_windows_bridge");

    for library in [
        "d3d11", "dxgi", "dxguid", "wer", "mfplat", "mf", "mfuuid", "ole32", "oleaut32", "propsys",
        "user32",
    ] {
        println!("cargo:rustc-link-lib={library}");
    }
}
