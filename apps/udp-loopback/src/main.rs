use latencydesk_frame::{FakeCapture, FakeCaptureConfig, Pattern, PixelFormat};
use latencydesk_protocol::{media_flags, MediaKind};
use latencydesk_socket_transport::{UdpEndpoint, DEFAULT_MAX_SOCKET_DATAGRAM};
use latencydesk_test_codec::ExactTestCodec;
use latencydesk_transport::{
    fragment_frame, FragmentSpec, IngestOutcome, Reassembler, ReassemblyConfig,
};
use std::error::Error;
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn Error>> {
    let (sender, receiver) = UdpEndpoint::connected_pair(DEFAULT_MAX_SOCKET_DATAGRAM)?;
    sender.set_timeout(Duration::from_secs(2))?;
    receiver.set_timeout(Duration::from_secs(2))?;
    let receive_thread = thread::spawn(move || -> Result<Vec<u8>, String> {
        let mut reassembler =
            Reassembler::new(ReassemblyConfig::default()).map_err(|error| error.to_string())?;
        let mut buffer = vec![0; DEFAULT_MAX_SOCKET_DATAGRAM];
        loop {
            let read = receiver
                .receive(&mut buffer)
                .map_err(|error| error.to_string())?;
            if let IngestOutcome::Complete(frame) = reassembler
                .ingest(&buffer[..read], 1)
                .map_err(|error| error.to_string())?
            {
                return Ok(frame.bytes);
            }
        }
    });

    let mut capture = FakeCapture::new(FakeCaptureConfig {
        width: 128,
        height: 72,
        format: PixelFormat::Bgra8,
        pattern: Pattern::TextLike,
        seed: 9,
    })?;
    let frame = capture.capture(0)?;
    let encoded = ExactTestCodec::encode(&frame)?;
    let datagrams = fragment_frame(
        FragmentSpec {
            kind: MediaKind::Video,
            flags: media_flags::KEYFRAME | media_flags::LOSSLESS,
            stream_id: 1,
            codec_epoch: 1,
            frame_id: 1,
            dependency_frame_id: None,
        },
        &encoded,
        DEFAULT_MAX_SOCKET_DATAGRAM,
    )?;
    for datagram in datagrams {
        let _ = sender.send(&datagram)?;
    }
    let reconstructed = receive_thread
        .join()
        .map_err(|_| "receiver thread panicked")?
        .map_err(|error| format!("receiver failed: {error}"))?;
    let decoded = ExactTestCodec::decode(&reconstructed, 1)?;
    if decoded.data != frame.data {
        return Err("UDP exact reconstruction mismatch".into());
    }
    println!(
        "UDP loopback reconstructed {} bytes exactly",
        decoded.data.len()
    );
    Ok(())
}
