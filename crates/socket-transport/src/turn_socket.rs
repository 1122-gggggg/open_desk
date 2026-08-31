//! Authenticated RFC 8656 TURN-over-UDP route for Quinn.
//!
//! The route is a deep module: callers can only obtain it by completing
//! Allocate (401 challenge, SHA-256 MESSAGE-INTEGRITY), CreatePermission, and
//! ChannelBind. One task owns every read and demultiplexes STUN replies from
//! ChannelData, so refreshes never race the application reader.

use latencydesk_turn_relay::{
    wire::{self, Attribute, Class, Header, Message, Method},
    PERMISSION_LIFETIME,
};
use quinn::{AsyncUdpSocket, UdpPoller};
use quinn_udp::{RecvMeta, Transmit};
use std::{
    collections::{HashMap, VecDeque},
    fmt, io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{oneshot, watch},
    task::JoinHandle,
    time::{self, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const ALLOCATION_LIFETIME: u64 = 600;
const MAX_QUEUE: usize = 64;
const MAX_QUEUE_BYTES: usize = MAX_QUEUE * MAX_PAYLOAD;
const MAX_PAYLOAD: usize = wire::MAX_DATAGRAM_BYTES - 4;
const MAX_PENDING_RESPONSES: usize = 4;
const INITIAL_RTO: Duration = Duration::from_millis(500);
const MAX_RTO: Duration = Duration::from_secs(4);
const MAX_REQUEST_ATTEMPTS: usize = 7;
const AUTHORITY_REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// Configuration for one authenticated TURN allocation.
pub struct TurnRouteConfig {
    pub server: SocketAddr,
    pub bind: SocketAddr,
    pub username: Vec<u8>,
    pub password: Vec<u8>,
    pub peer: SocketAddr,
    pub channel: u16,
    pub timeout: Duration,
}

impl Drop for TurnRouteConfig {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
    }
}

impl fmt::Debug for TurnRouteConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnRouteConfig")
            .field("server", &self.server)
            .field("bind", &self.bind)
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .field("peer", &self.peer)
            .field("channel", &self.channel)
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// A live, authenticated TURN route. No raw-socket constructor is exposed;
/// use [`AuthenticatedTurnRoute::establish`].
pub struct AuthenticatedTurnRoute {
    inner: Arc<Inner>,
    reader: Option<JoinHandle<()>>,
    refresh: Option<JoinHandle<()>>,
}

struct EstablishGuard {
    inner: Arc<Inner>,
    reader: Option<JoinHandle<()>>,
    armed: bool,
}

impl EstablishGuard {
    fn complete(mut self, refresh: JoinHandle<()>) -> AuthenticatedTurnRoute {
        self.armed = false;
        AuthenticatedTurnRoute {
            inner: Arc::clone(&self.inner),
            reader: self.reader.take(),
            refresh: Some(refresh),
        }
    }
}

impl Drop for EstablishGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.inner.revoke();
        if let Some(reader) = self.reader.take() {
            reader.abort();
        }
    }
}

/// Compatibility name for the old adapter without preserving its raw API.
pub type TurnChannelSocket = AuthenticatedTurnRoute;

struct Inner {
    socket: Arc<UdpSocket>,
    server: SocketAddr,
    peer: SocketAddr,
    channel: u16,
    relayed: Mutex<SocketAddr>,
    state: Mutex<LiveState>,
    responses: Mutex<HashMap<[u8; 12], PendingResponse>>,
    queue: Mutex<VecDeque<Vec<u8>>>,
    queue_bytes: Mutex<usize>,
    queue_waker: Mutex<Option<Waker>>,
    stop: watch::Sender<bool>,
    credentials: Mutex<Option<RefreshCredentials>>,
    password: Zeroizing<Vec<u8>>,
    auth_lock: tokio::sync::Mutex<()>,
    timeout: Duration,
}

struct PendingResponse {
    sender: oneshot::Sender<Vec<u8>>,
    require_integrity: bool,
    integrity_key: Option<Zeroizing<[u8; 32]>>,
}

struct LiveState {
    expiry: Instant,
    generation: u64,
    revoked: bool,
}

struct RefreshCredentials {
    username: Zeroizing<Vec<u8>>,
    realm: Zeroizing<Vec<u8>>,
    nonce: Zeroizing<Vec<u8>>,
    key: Zeroizing<[u8; 32]>,
}

type ClonedCredentials = (
    Zeroizing<Vec<u8>>,
    Zeroizing<Vec<u8>>,
    Zeroizing<Vec<u8>>,
    Zeroizing<[u8; 32]>,
);

struct PendingResponseGuard {
    inner: Arc<Inner>,
    id: [u8; 12],
    armed: bool,
}

impl PendingResponseGuard {
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for PendingResponseGuard {
    fn drop(&mut self) {
        if self.armed {
            self.inner
                .responses
                .lock()
                .expect("response mutex poisoned")
                .remove(&self.id);
        }
    }
}

impl AuthenticatedTurnRoute {
    /// Establish an authenticated allocation and bind exactly one peer and
    /// channel. This is the only public construction path.
    pub async fn establish(mut config: TurnRouteConfig) -> io::Result<Self> {
        validate_config(&config)?;
        let socket = Arc::new(UdpSocket::bind(config.bind).await?);
        let (stop, _) = watch::channel(false);
        let username = Zeroizing::new(std::mem::take(&mut config.username));
        let password = Zeroizing::new(std::mem::take(&mut config.password));
        let server = config.server;
        let peer = config.peer;
        let channel = config.channel;
        let inner = Arc::new(Inner {
            socket,
            server,
            peer,
            channel,
            relayed: Mutex::new(server),
            state: Mutex::new(LiveState {
                expiry: Instant::now() + config.timeout,
                generation: 0,
                revoked: false,
            }),
            responses: Mutex::new(HashMap::new()),
            queue: Mutex::new(VecDeque::new()),
            queue_bytes: Mutex::new(0),
            queue_waker: Mutex::new(None),
            stop,
            credentials: Mutex::new(None),
            password: password.clone(),
            auth_lock: tokio::sync::Mutex::new(()),
            timeout: config.timeout,
        });
        let reader_inner = inner.clone();
        let reader = tokio::spawn(read_loop(reader_inner));
        let guard = EstablishGuard {
            inner: Arc::clone(&inner),
            reader: Some(reader),
            armed: true,
        };

        let (relayed, expiry) =
            establish_transcript(&inner, server, peer, channel, &username, &password).await?;
        {
            let mut state = inner.state.lock().expect("state mutex poisoned");
            if state.revoked {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "TURN route revoked",
                ));
            }
            state.expiry = expiry;
            state.generation = 1;
        }
        *inner.relayed.lock().expect("relayed mutex poisoned") = relayed;

        let refresh_inner = inner.clone();
        let refresh = tokio::spawn(refresh_loop(refresh_inner));
        Ok(guard.complete(refresh))
    }

    /// Build a Quinn endpoint around this route while retaining the caller's
    /// exact-mTLS [`quinn::ClientConfig`].
    pub fn into_quinn_endpoint(
        self: Arc<Self>,
        endpoint_config: quinn::EndpointConfig,
        client_config: quinn::ClientConfig,
    ) -> io::Result<quinn::Endpoint> {
        let runtime =
            quinn::default_runtime().ok_or_else(|| io::Error::other("no Quinn runtime"))?;
        let mut endpoint =
            quinn::Endpoint::new_with_abstract_socket(endpoint_config, None, self, runtime)?;
        endpoint.set_default_client_config(client_config);
        Ok(endpoint)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.live()?;
        Ok(*self.inner.relayed.lock().expect("relayed mutex poisoned"))
    }

    pub fn generation(&self) -> u64 {
        self.inner
            .state
            .lock()
            .expect("state mutex poisoned")
            .generation
    }

    pub fn expires_at(&self) -> Instant {
        self.inner
            .state
            .lock()
            .expect("state mutex poisoned")
            .expiry
    }

    /// Send Refresh(0) and then revoke the local route. Repeated calls are safe.
    pub async fn shutdown(&self) -> io::Result<()> {
        // Keep the route live while the deallocation request is in flight;
        // request() itself rejects revoked routes.
        let should_deallocate = {
            let state = self.inner.state.lock().expect("state mutex poisoned");
            !state.revoked
        };
        if should_deallocate {
            let result = refresh_request(&self.inner, 0).await;
            self.inner.mark_revoked();
            self.inner.stop_tasks();
            return result.map(|_| ());
        }
        self.inner.stop_tasks();
        Ok(())
    }

    fn live(&self) -> io::Result<()> {
        self.inner.ensure_live()
    }
}

impl Inner {
    fn ensure_live(&self) -> io::Result<()> {
        let state = self.state.lock().expect("state mutex poisoned");
        if state.revoked || Instant::now() >= state.expiry {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TURN route expired or revoked",
            ));
        }
        Ok(())
    }

    fn mark_revoked(&self) -> bool {
        let mut state = self.state.lock().expect("state mutex poisoned");
        if state.revoked {
            false
        } else {
            state.revoked = true;
            true
        }
    }

    fn revoke(&self) {
        self.mark_revoked();
        self.stop_tasks();
    }

    fn stop_tasks(&self) {
        let _ = self.stop.send(true);
        if let Some(waker) = self
            .queue_waker
            .lock()
            .expect("queue waker poisoned")
            .take()
        {
            waker.wake();
        }
        self.responses
            .lock()
            .expect("response mutex poisoned")
            .clear();
        self.queue.lock().expect("queue mutex poisoned").clear();
        *self.queue_bytes.lock().expect("queue byte mutex poisoned") = 0;
    }
}

impl Drop for AuthenticatedTurnRoute {
    fn drop(&mut self) {
        // Drop cannot await Refresh(0); revoke locally and abort both workers.
        self.inner.revoke();
        if let Some(task) = self.reader.take() {
            task.abort();
        }
        if let Some(task) = self.refresh.take() {
            task.abort();
        }
    }
}

impl fmt::Debug for AuthenticatedTurnRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedTurnRoute")
            .field("server", &self.inner.server)
            .field("peer", &self.inner.peer)
            .field("channel", &self.inner.channel)
            .field("generation", &self.generation())
            .finish()
    }
}

impl AsyncUdpSocket for AuthenticatedTurnRoute {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(TurnPoller { route: self })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.live()?;
        if transmit.destination != self.inner.peer
            || transmit.contents.len() > MAX_PAYLOAD
            || transmit.segment_size.is_some()
            || transmit.src_ip.is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "TURN transmit binding mismatch",
            ));
        }
        let encoded =
            wire::encode_channel_data(self.inner.channel, transmit.contents).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TURN ChannelData bounds failed",
                )
            })?;
        match self.inner.socket.try_send_to(&encoded, self.inner.server) {
            Ok(written) if written == encoded.len() => Ok(()),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short TURN datagram",
            )),
            Err(error) => Err(error),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Err(error) = self.live() {
            return Poll::Ready(Err(error));
        }
        let mut queue = self.inner.queue.lock().expect("queue mutex poisoned");
        // A datagram that fits the TURN wire limit can still exceed the
        // buffer Quinn supplied.  Drop only that bounded queue entry and
        // continue so one peer cannot turn a malformed/oversize frame into a
        // fatal endpoint error or permanently stall the receive path.
        while let Some(payload) = queue.pop_front() {
            let payload_len = payload.len();
            let mut queued_bytes = self
                .inner
                .queue_bytes
                .lock()
                .expect("queue byte mutex poisoned");
            *queued_bytes = queued_bytes.saturating_sub(payload_len);
            drop(queued_bytes);
            if payload.len() > bufs[0].len() {
                continue;
            }
            bufs[0][..payload.len()].copy_from_slice(&payload);
            meta[0] = RecvMeta {
                addr: self.inner.peer,
                len: payload.len(),
                stride: payload.len(),
                ecn: None,
                dst_ip: None,
            };
            return Poll::Ready(Ok(1));
        }
        drop(queue);
        *self.inner.queue_waker.lock().expect("queue waker poisoned") = Some(cx.waker().clone());
        if !self
            .inner
            .queue
            .lock()
            .expect("queue mutex poisoned")
            .is_empty()
        {
            if let Some(waker) = self
                .inner
                .queue_waker
                .lock()
                .expect("queue waker poisoned")
                .take()
            {
                waker.wake();
            }
        }
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        AuthenticatedTurnRoute::local_addr(self)
    }
    fn max_transmit_segments(&self) -> usize {
        1
    }
    fn max_receive_segments(&self) -> usize {
        1
    }
    fn may_fragment(&self) -> bool {
        true
    }
}

struct TurnPoller {
    route: Arc<AuthenticatedTurnRoute>,
}
impl fmt::Debug for TurnPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnPoller").finish()
    }
}
impl UdpPoller for TurnPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.route.inner.socket.poll_send_ready(cx)
    }
}

async fn read_loop(inner: Arc<Inner>) {
    let mut stop = inner.stop.subscribe();
    let mut buffer = vec![0_u8; wire::MAX_DATAGRAM_BYTES];
    loop {
        tokio::select! {
            changed = stop.changed() => if changed.is_err() || *stop.borrow() { return; },
            received = inner.socket.recv_from(&mut buffer) => {
                let Ok((length, source)) = received else {
                    inner.revoke();
                    return;
                };
                if inner.ensure_live().is_err() {
                    inner.revoke();
                    return;
                }
                if source != inner.server || length == 0 || length > wire::MAX_DATAGRAM_BYTES { continue; }
                let datagram = &buffer[..length];
                if let Ok((channel, payload)) = wire::decode_channel_data(datagram) {
                    if channel != inner.channel || payload.len() > MAX_PAYLOAD { continue; }
                    enqueue_payload(&inner, payload);
                    if let Some(waker) = inner.queue_waker.lock().expect("queue waker poisoned").take() { waker.wake(); }
                    continue;
                }
                let Ok(message) = wire::decode(datagram) else { continue; };
                if !matches!(message.header.class, Class::Success | Class::Error) { continue; }
                let mut responses = inner.responses.lock().expect("response mutex poisoned");
                let Some(pending) = responses.get(&message.header.transaction_id) else {
                    continue;
                };
                let has_integrity = message.attributes.iter().any(|attribute| {
                    matches!(attribute, Attribute::MessageIntegritySha256(_))
                });
                // 9.2.5: responses without MESSAGE-INTEGRITY are discarded,
                // except the deliberately unauthenticated Allocate/401
                // bootstrap challenge.  Authenticated transactions remain
                // pending so their bounded retransmission schedule can run.
                let bootstrap_unauthenticated_challenge = !pending.require_integrity
                    && message.header.method == Method::Allocate
                    && message.header.class == Class::Error
                    && error_code(&message) == Some(401)
                    && !has_integrity;
                if bootstrap_unauthenticated_challenge {
                    // This is the only intentionally unsigned response: the
                    // initial Allocate/401 challenge has no key yet.
                } else {
                    let Some(key) = pending.integrity_key.as_ref() else {
                        continue;
                    };
                    if wire::verify_integrity(datagram, key.as_ref()).is_err() {
                        continue;
                    }
                }
                if let Some(pending) = responses.remove(&message.header.transaction_id) {
                    let _ = pending.sender.send(datagram.to_vec());
                }
            }
        }
    }
}

fn enqueue_payload(inner: &Inner, payload: &[u8]) {
    let mut queue = inner.queue.lock().expect("queue mutex poisoned");
    let mut queue_bytes = inner.queue_bytes.lock().expect("queue byte mutex poisoned");
    if queue.len() < MAX_QUEUE && queue_bytes.saturating_add(payload.len()) <= MAX_QUEUE_BYTES {
        queue.push_back(payload.to_vec());
        *queue_bytes += payload.len();
    }
}

async fn establish_transcript(
    inner: &Arc<Inner>,
    server: SocketAddr,
    peer: SocketAddr,
    channel: u16,
    username: &[u8],
    password: &[u8],
) -> io::Result<(SocketAddr, Instant)> {
    let challenge_id = transaction_id()?;
    let challenge = Message {
        header: Header {
            class: Class::Request,
            method: Method::Allocate,
            transaction_id: challenge_id,
        },
        attributes: vec![
            Attribute::RequestedTransport(17),
            Attribute::Lifetime(ALLOCATION_LIFETIME as u32),
        ],
    };
    let challenge = request(
        inner,
        wire::encode(&challenge).map_err(wire_error)?,
        challenge_id,
    )
    .await?;
    let challenge = wire::decode(&challenge).map_err(wire_error)?;
    if challenge.header.method == Method::Allocate
        && challenge.header.transaction_id == challenge_id
        && error_code(&challenge) == Some(438)
    {
        return Err(protocol_error(
            "TURN Allocate returned stale nonce before authentication",
        ));
    }
    if challenge.header.class != Class::Error
        || challenge.header.method != Method::Allocate
        || error_code(&challenge) != Some(401)
    {
        return Err(protocol_error("TURN Allocate did not return 401"));
    }
    let realm = Zeroizing::new(required_bytes(&challenge, true)?.to_vec());
    let nonce = Zeroizing::new(required_bytes(&challenge, false)?.to_vec());
    let key = Zeroizing::new(*wire::derive_long_term_key_sha256(
        username, &realm, password,
    ));

    // Install the bootstrap credentials before the authenticated Allocate so
    // every post-401 transaction uses the same typed 438 recovery path.
    *inner
        .credentials
        .lock()
        .expect("credentials mutex poisoned") = Some(RefreshCredentials {
        username: Zeroizing::new(username.to_vec()),
        realm,
        nonce,
        key,
    });

    let allocation = authenticated_request(
        inner,
        Method::Allocate,
        vec![
            Attribute::RequestedTransport(17),
            Attribute::Lifetime(ALLOCATION_LIFETIME as u32),
        ],
    )
    .await?;
    let relayed = allocation
        .message()
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            Attribute::XorRelayedAddress(address) => Some(*address),
            _ => None,
        })
        .ok_or_else(|| protocol_error("TURN Allocate omitted relay address"))?;
    validate_relayed(relayed, server)?;
    let lifetime = allocation
        .message()
        .attributes
        .iter()
        .find_map(|attribute| {
            if let Attribute::Lifetime(value) = attribute {
                Some((*value as u64).min(ALLOCATION_LIFETIME))
            } else {
                None
            }
        })
        .ok_or_else(|| protocol_error("TURN Allocate omitted lifetime"))?;
    if lifetime == 0 {
        return Err(protocol_error("TURN Allocate returned zero lifetime"));
    }

    let _permission = authenticated_request(
        inner,
        Method::CreatePermission,
        vec![Attribute::XorPeerAddress(peer)],
    )
    .await?;
    let _binding = authenticated_request(
        inner,
        Method::ChannelBind,
        vec![
            Attribute::ChannelNumber(channel),
            Attribute::XorPeerAddress(peer),
        ],
    )
    .await?;
    Ok((
        relayed,
        Instant::now() + Duration::from_secs(lifetime.max(1)),
    ))
}

async fn refresh_loop(inner: Arc<Inner>) {
    loop {
        let (expiry, generation) = {
            let state = inner.state.lock().expect("state mutex poisoned");
            if state.revoked {
                return;
            }
            (state.expiry, state.generation)
        };
        let permission_refresh =
            Duration::from_secs(PERMISSION_LIFETIME).saturating_sub(AUTHORITY_REFRESH_MARGIN);
        let delay = (expiry.saturating_duration_since(Instant::now()) / 2).min(permission_refresh);
        let timer = time::sleep(delay.max(Duration::from_millis(50)));
        tokio::pin!(timer);
        let mut stop = inner.stop.subscribe();
        tokio::select! { _ = &mut timer => {}, changed = stop.changed() => { let _ = changed; return; } }
        if inner.ensure_live().is_err() {
            return;
        }
        if let Ok(lifetime) = refresh_request(&inner, ALLOCATION_LIFETIME as u32).await {
            if renew_peer_authority(&inner).await.is_err() {
                inner.revoke();
                return;
            }
            let mut state = inner.state.lock().expect("state mutex poisoned");
            if !state.revoked && state.generation == generation {
                state.generation = state.generation.saturating_add(1);
                state.expiry = Instant::now() + Duration::from_secs(lifetime);
            }
        } else {
            inner.revoke();
            return;
        }
    }
}

async fn renew_peer_authority(inner: &Arc<Inner>) -> io::Result<()> {
    for (method, attributes) in [
        (
            Method::CreatePermission,
            vec![Attribute::XorPeerAddress(inner.peer)],
        ),
        (
            Method::ChannelBind,
            vec![
                Attribute::ChannelNumber(inner.channel),
                Attribute::XorPeerAddress(inner.peer),
            ],
        ),
    ] {
        let _ = authenticated_request(inner, method, attributes).await?;
    }
    Ok(())
}

fn cloned_credentials(inner: &Inner) -> io::Result<ClonedCredentials> {
    let credentials = inner
        .credentials
        .lock()
        .expect("credentials mutex poisoned");
    let credentials = credentials
        .as_ref()
        .ok_or_else(|| protocol_error("TURN credentials unavailable"))?;
    Ok((
        credentials.username.clone(),
        credentials.realm.clone(),
        credentials.nonce.clone(),
        credentials.key.clone(),
    ))
}

async fn refresh_request(inner: &Arc<Inner>, lifetime: u32) -> io::Result<u64> {
    let response =
        authenticated_request(inner, Method::Refresh, vec![Attribute::Lifetime(lifetime)]).await?;
    let returned = response
        .message()
        .attributes
        .iter()
        .find_map(|attribute| {
            if let Attribute::Lifetime(value) = attribute {
                Some(u64::from(*value))
            } else {
                None
            }
        })
        .ok_or_else(|| protocol_error("TURN Refresh omitted lifetime"))?;
    if lifetime == 0 {
        if returned != 0 {
            return Err(protocol_error("TURN Refresh(0) was not honored"));
        }
    } else if returned == 0 {
        return Err(protocol_error("TURN Refresh returned zero lifetime"));
    }
    Ok(returned)
}

struct StaleChallenge {
    realm: Zeroizing<Vec<u8>>,
    nonce: Zeroizing<Vec<u8>>,
}

/// Send one authenticated request.  A 438 challenge is accepted only when
/// the demultiplexer has already proven the datagram came from the configured
/// TURN server and the response's method/transaction/error tuple is exact.
/// The new credentials are installed as one mutex operation and are used for
/// at most one re-signed retry; 401 and a second 438 are terminal failures.
async fn authenticated_request(
    inner: &Arc<Inner>,
    method: Method,
    attributes: Vec<Attribute>,
) -> io::Result<wire::VerifiedMessage> {
    let _auth_guard = inner.auth_lock.lock().await;
    let mut retried = false;
    loop {
        let (username, realm, nonce, key) = cloned_credentials(inner)?;
        let id = transaction_id()?;
        let encoded = signed_request(
            method,
            id,
            &username,
            &realm,
            &nonce,
            attributes.clone(),
            key.as_ref(),
        )?;
        let response = request_with_policy(inner, encoded, id, true, Some(key.clone())).await?;
        match verify_authenticated_response(&response, method, id, key.as_ref())? {
            Ok(response) => return Ok(response),
            Err(challenge) if !retried => {
                replace_credentials(inner, &realm, &nonce, challenge.realm, challenge.nonce)?;
                retried = true;
            }
            Err(_) => {
                return Err(protocol_error("TURN stale nonce retry exhausted"));
            }
        }
    }
}

fn verify_authenticated_response(
    encoded: &[u8],
    method: Method,
    id: [u8; 12],
    key: &[u8],
) -> io::Result<Result<wire::VerifiedMessage, StaleChallenge>> {
    let message = wire::decode(encoded).map_err(wire_error)?;
    if message.header.method != method || message.header.transaction_id != id {
        return Err(protocol_error(
            "TURN response method or transaction mismatch",
        ));
    }
    if message.header.class == Class::Error && error_code(&message) == Some(438) {
        let realm = Zeroizing::new(required_bytes(&message, true)?.to_vec());
        let nonce = Zeroizing::new(required_bytes(&message, false)?.to_vec());
        if realm.is_empty() || nonce.is_empty() {
            return Err(protocol_error("TURN stale nonce challenge is incomplete"));
        }
        // RFC 8489 9.2.5: an authenticated UDP response, including a 438
        // challenge, must carry integrity verified with the old credentials.
        wire::verify_integrity(encoded, key).map_err(wire_error)?;
        return Ok(Err(StaleChallenge { realm, nonce }));
    }
    let response = wire::verify_integrity(encoded, key).map_err(wire_error)?;
    require_success(response.message(), method, id)?;
    Ok(Ok(response))
}

fn replace_credentials(
    inner: &Arc<Inner>,
    old_realm: &[u8],
    old_nonce: &[u8],
    realm: Zeroizing<Vec<u8>>,
    nonce: Zeroizing<Vec<u8>>,
) -> io::Result<()> {
    let mut credentials = inner
        .credentials
        .lock()
        .expect("credentials mutex poisoned");
    let current = credentials
        .as_ref()
        .ok_or_else(|| protocol_error("TURN credentials unavailable"))?;
    // A concurrent refresh may already have advanced the nonce.  Preserve
    // that newer generation rather than rolling credentials backwards.
    if current.realm.as_slice() != old_realm || current.nonce.as_slice() != old_nonce {
        return Ok(());
    }
    let key = wire::derive_long_term_key_sha256(
        current.username.as_ref(),
        realm.as_ref(),
        inner.password.as_ref(),
    );
    *credentials = Some(RefreshCredentials {
        username: current.username.clone(),
        realm,
        nonce,
        key,
    });
    Ok(())
}

async fn request(inner: &Arc<Inner>, encoded: Vec<u8>, id: [u8; 12]) -> io::Result<Vec<u8>> {
    request_with_policy(inner, encoded, id, false, None).await
}

async fn request_with_policy(
    inner: &Arc<Inner>,
    encoded: Vec<u8>,
    id: [u8; 12],
    require_integrity: bool,
    integrity_key: Option<Zeroizing<[u8; 32]>>,
) -> io::Result<Vec<u8>> {
    inner.ensure_live()?;
    let (sender, receiver) = oneshot::channel();
    {
        let mut responses = inner.responses.lock().expect("response mutex poisoned");
        if responses.len() >= MAX_PENDING_RESPONSES {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "TURN transaction capacity exhausted",
            ));
        }
        if responses
            .insert(
                id,
                PendingResponse {
                    sender,
                    require_integrity,
                    integrity_key,
                },
            )
            .is_some()
        {
            responses.remove(&id);
            return Err(protocol_error("duplicate TURN transaction"));
        }
    }
    let guard = PendingResponseGuard {
        inner: Arc::clone(inner),
        id,
        armed: true,
    };
    let deadline = Instant::now() + inner.timeout;
    let mut receiver = receiver;
    let mut rto = INITIAL_RTO;
    for attempt in 0..MAX_REQUEST_ATTEMPTS {
        if Instant::now() >= deadline {
            break;
        }
        time::timeout_at(deadline, inner.socket.send_to(&encoded, inner.server))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TURN transaction timeout"))??;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let wait = remaining.min(rto);
        match time::timeout(wait, &mut receiver).await {
            Ok(Ok(response)) => {
                guard.disarm();
                return Ok(response);
            }
            Ok(Err(_)) => break,
            Err(_) => {
                if attempt + 1 < MAX_REQUEST_ATTEMPTS {
                    rto = rto.saturating_mul(2).min(MAX_RTO);
                }
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "TURN transaction timeout",
    ))
}

fn signed_request(
    method: Method,
    id: [u8; 12],
    username: &[u8],
    realm: &[u8],
    nonce: &[u8],
    mut attributes: Vec<Attribute>,
    key: &[u8],
) -> io::Result<Vec<u8>> {
    let mut credentials = vec![
        Attribute::Username(username.to_vec()),
        Attribute::Realm(realm.to_vec()),
        Attribute::Nonce(nonce.to_vec()),
    ];
    credentials.append(&mut attributes);
    wire::encode_with_integrity(
        &Message {
            header: Header {
                class: Class::Request,
                method,
                transaction_id: id,
            },
            attributes: credentials,
        },
        key,
    )
    .map_err(wire_error)
}

fn validate_config(config: &TurnRouteConfig) -> io::Result<()> {
    if config.server.port() == 0
        || config.peer.port() == 0
        || config.server == config.peer
        || unusable(config.server)
        || unusable(config.peer)
        || unusable(config.bind)
        || config.server.is_ipv4() != config.bind.is_ipv4()
        || config.server.is_ipv4() != config.peer.is_ipv4()
        || config.username.is_empty()
        || config.username.len() > 512
        || config.password.len() < 16
        || config.password.len() > 512
        || config.timeout.is_zero()
        || config.timeout > Duration::from_secs(120)
        || !(wire::CHANNEL_MIN..=wire::CHANNEL_MAX).contains(&config.channel)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid TURN route configuration",
        ));
    }
    Ok(())
}

fn unusable(address: SocketAddr) -> bool {
    address.ip().is_unspecified()
        || address.ip().is_multicast()
        || matches!(address.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
}

fn validate_relayed(relayed: SocketAddr, server: SocketAddr) -> io::Result<()> {
    if relayed.port() == 0
        || unusable(relayed)
        || relayed == server
        || relayed.is_ipv4() != server.is_ipv4()
    {
        return Err(protocol_error("TURN returned an invalid relay address"));
    }
    Ok(())
}

fn transaction_id() -> io::Result<[u8; 12]> {
    let mut id = [0_u8; 12];
    getrandom::getrandom(&mut id)
        .map_err(|_| io::Error::other("TURN transaction randomness failed"))?;
    if id == [0; 12] {
        return Err(io::Error::other(
            "TURN transaction randomness returned zero",
        ));
    }
    Ok(id)
}
fn required_bytes(message: &Message, realm: bool) -> io::Result<&[u8]> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match (realm, attribute) {
            (true, Attribute::Realm(value)) | (false, Attribute::Nonce(value)) => {
                Some(value.as_slice())
            }
            _ => None,
        })
        .ok_or_else(|| protocol_error("TURN challenge omitted credentials"))
}
fn error_code(message: &Message) -> Option<u16> {
    message.attributes.iter().find_map(|attribute| {
        if let Attribute::ErrorCode { code, .. } = attribute {
            Some(*code)
        } else {
            None
        }
    })
}
fn require_success(message: &Message, method: Method, id: [u8; 12]) -> io::Result<()> {
    if message.header.class == Class::Error {
        return Err(protocol_error("TURN transaction returned an error"));
    }
    if message.header.class != Class::Success
        || message.header.method != method
        || message.header.transaction_id != id
    {
        return Err(protocol_error("TURN transcript mismatch"));
    }
    Ok(())
}
fn protocol_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn wire_error(_: wire::WireError) -> io::Error {
    protocol_error("invalid TURN wire message")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::IoSliceMut;
    use std::sync::Arc;

    fn bare_inner(socket: Arc<UdpSocket>, server: SocketAddr, timeout: Duration) -> Arc<Inner> {
        Arc::new(Inner {
            socket,
            server,
            peer: "127.0.0.1:4000".parse().unwrap(),
            channel: 0x4000,
            relayed: Mutex::new("127.0.0.1:49000".parse().unwrap()),
            state: Mutex::new(LiveState {
                expiry: Instant::now() + Duration::from_secs(10),
                generation: 1,
                revoked: false,
            }),
            responses: Mutex::new(HashMap::new()),
            queue: Mutex::new(VecDeque::new()),
            queue_bytes: Mutex::new(0),
            queue_waker: Mutex::new(None),
            stop: watch::channel(false).0,
            credentials: Mutex::new(None),
            password: Zeroizing::new(Vec::new()),
            auth_lock: tokio::sync::Mutex::new(()),
            timeout,
        })
    }

    #[test]
    fn config_debug_redacts_secret_and_accepts_ephemeral_bind() {
        let config = TurnRouteConfig {
            server: "127.0.0.1:3478".parse().unwrap(),
            bind: "127.0.0.1:0".parse().unwrap(),
            username: b"alice".to_vec(),
            password: b"0123456789abcdef-password".to_vec(),
            peer: "127.0.0.1:4000".parse().unwrap(),
            channel: 0x4000,
            timeout: Duration::from_secs(5),
        };
        assert!(!format!("{config:?}").contains("0123456789"));
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn max_payload_matches_channel_data_wire_bound() {
        assert_eq!(MAX_PAYLOAD + 4, wire::MAX_DATAGRAM_BYTES);
    }

    #[test]
    fn retransmission_schedule_is_bounded_exponential() {
        let mut delay = INITIAL_RTO;
        let mut schedule = Vec::new();
        for _ in 0..MAX_REQUEST_ATTEMPTS {
            schedule.push(delay);
            delay = delay.saturating_mul(2).min(MAX_RTO);
        }
        assert_eq!(
            schedule,
            vec![
                Duration::from_millis(500),
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(4),
                Duration::from_secs(4),
                Duration::from_secs(4),
            ]
        );
        assert!(schedule.windows(2).all(|window| window[1] >= window[0]));
        assert!(schedule.iter().all(|value| *value <= MAX_RTO));
    }

    #[test]
    fn relayed_address_cannot_be_the_control_server() {
        let server = "127.0.0.1:3478".parse().unwrap();
        assert!(validate_relayed(server, server).is_err());
    }

    #[test]
    fn authenticated_438_requires_exact_response_tuple_and_challenge() {
        let id = [7_u8; 12];
        let response_message = Message {
            header: Header {
                class: Class::Error,
                method: Method::Refresh,
                transaction_id: id,
            },
            attributes: vec![
                Attribute::ErrorCode {
                    code: 438,
                    reason: "Stale Nonce".into(),
                },
                Attribute::Realm(b"new.realm".to_vec()),
                Attribute::Nonce(b"new-nonce".to_vec()),
            ],
        };
        let key = [0_u8; 32];
        let response = wire::encode_with_integrity(&response_message, &key).unwrap();
        let challenge = verify_authenticated_response(&response, Method::Refresh, id, &key)
            .unwrap()
            .unwrap_err();
        assert_eq!(challenge.realm.as_slice(), b"new.realm");
        assert_eq!(challenge.nonce.as_slice(), b"new-nonce");

        let unsigned = wire::encode(&response_message).unwrap();
        assert!(verify_authenticated_response(&unsigned, Method::Refresh, id, &key).is_err());

        let wrong_method = wire::encode(&Message {
            header: Header {
                class: Class::Error,
                method: Method::Allocate,
                transaction_id: id,
            },
            attributes: vec![Attribute::ErrorCode {
                code: 438,
                reason: "Stale Nonce".into(),
            }],
        })
        .unwrap();
        assert!(
            verify_authenticated_response(&wrong_method, Method::Refresh, id, &[0_u8; 32]).is_err()
        );
    }

    #[tokio::test]
    async fn poll_recv_drops_oversize_then_delivers_valid_payload() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (stop, _) = watch::channel(false);
        let server = "127.0.0.1:3478".parse().unwrap();
        let peer = "127.0.0.1:4000".parse().unwrap();
        let inner = Arc::new(Inner {
            socket,
            server,
            peer,
            channel: 0x4000,
            relayed: Mutex::new("127.0.0.1:49000".parse().unwrap()),
            state: Mutex::new(LiveState {
                expiry: Instant::now() + Duration::from_secs(5),
                generation: 1,
                revoked: false,
            }),
            responses: Mutex::new(HashMap::new()),
            queue: Mutex::new(VecDeque::from([vec![0_u8; 32], b"valid".to_vec()])),
            queue_bytes: Mutex::new(37),
            queue_waker: Mutex::new(None),
            stop,
            credentials: Mutex::new(None),
            password: Zeroizing::new(Vec::new()),
            auth_lock: tokio::sync::Mutex::new(()),
            timeout: Duration::from_secs(1),
        });
        let route = AuthenticatedTurnRoute {
            inner,
            reader: None,
            refresh: None,
        };
        let mut output = [0_u8; 8];
        let mut metadata = [RecvMeta::default()];
        let received = std::future::poll_fn(|cx| {
            let mut slices = [IoSliceMut::new(&mut output)];
            route.poll_recv(cx, &mut slices, &mut metadata)
        })
        .await
        .unwrap();
        assert_eq!(received, 1);
        assert_eq!(&output[..metadata[0].len], b"valid");
        assert_eq!(*route.inner.queue_bytes.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn queue_enforces_item_and_byte_caps_and_accounts_pops() {
        let inner = bare_inner(
            Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            "127.0.0.1:3478".parse().unwrap(),
            Duration::from_secs(1),
        );
        let payload = vec![0_u8; MAX_PAYLOAD];
        for _ in 0..MAX_QUEUE {
            enqueue_payload(&inner, &payload);
        }
        enqueue_payload(&inner, &[1_u8]);
        assert_eq!(inner.queue.lock().unwrap().len(), MAX_QUEUE);
        assert_eq!(*inner.queue_bytes.lock().unwrap(), MAX_QUEUE_BYTES);
        let route = AuthenticatedTurnRoute {
            inner,
            reader: None,
            refresh: None,
        };
        let mut output = vec![0_u8; MAX_PAYLOAD];
        let mut metadata = [RecvMeta::default()];
        let received = std::future::poll_fn(|cx| {
            let mut slices = [IoSliceMut::new(&mut output)];
            route.poll_recv(cx, &mut slices, &mut metadata)
        })
        .await
        .unwrap();
        assert_eq!(received, 1);
        assert_eq!(
            *route.inner.queue_bytes.lock().unwrap(),
            MAX_QUEUE_BYTES - MAX_PAYLOAD
        );
    }

    #[tokio::test]
    async fn authenticated_establish_uses_one_reader_and_shutdown_refresh_zero() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let password = b"0123456789abcdef-password".to_vec();
        let server_password = password.clone();
        let server_task = tokio::spawn(async move {
            let mut datagram = vec![0_u8; wire::MAX_DATAGRAM_BYTES];
            let realm = b"local.test".to_vec();
            let nonce = b"nonce-1".to_vec();
            let mut active_realm = realm.clone();
            let mut active_nonce = nonce.clone();
            let mut stale_methods = Vec::new();
            let mut permission_count = 0;
            let mut channel_count = 0;
            let saw_refresh_zero = loop {
                let (length, source) =
                    time::timeout(Duration::from_secs(3), server.recv_from(&mut datagram))
                        .await
                        .unwrap()
                        .unwrap();
                if let Ok((channel, payload)) = wire::decode_channel_data(&datagram[..length]) {
                    if channel == 0x4000 {
                        assert!(matches!(payload, b"outbound" | b"ecn"));
                    }
                    continue;
                }
                let message = wire::decode(&datagram[..length]).unwrap();
                if message.header.method == Method::Allocate
                    && !message
                        .attributes
                        .iter()
                        .any(|attribute| matches!(attribute, Attribute::MessageIntegritySha256(_)))
                {
                    let challenge = Message {
                        header: Header {
                            class: Class::Error,
                            method: Method::Allocate,
                            transaction_id: message.header.transaction_id,
                        },
                        attributes: vec![
                            Attribute::ErrorCode {
                                code: 401,
                                reason: "Unauthorized".into(),
                            },
                            Attribute::Realm(realm.clone()),
                            Attribute::Nonce(nonce.clone()),
                        ],
                    };
                    server
                        .send_to(&wire::encode(&challenge).unwrap(), source)
                        .await
                        .unwrap();
                    continue;
                }
                let key =
                    wire::derive_long_term_key_sha256(b"alice", &active_realm, &server_password);
                let verified = wire::verify_integrity(&datagram[..length], key.as_ref()).unwrap();
                let method = verified.message().header.method;
                if !stale_methods.contains(&method) {
                    stale_methods.push(method);
                    let next_realm = [active_realm.as_slice(), b"-rotated"].concat();
                    let next_nonce = [active_nonce.as_slice(), b"-rotated"].concat();
                    let stale = Message {
                        header: Header {
                            class: Class::Error,
                            method,
                            transaction_id: verified.message().header.transaction_id,
                        },
                        attributes: vec![
                            Attribute::ErrorCode {
                                code: 438,
                                reason: "Stale Nonce".into(),
                            },
                            Attribute::Realm(next_realm.clone()),
                            Attribute::Nonce(next_nonce.clone()),
                        ],
                    };
                    server
                        .send_to(
                            &wire::encode_with_integrity(&stale, key.as_ref()).unwrap(),
                            source,
                        )
                        .await
                        .unwrap();
                    active_realm = next_realm;
                    active_nonce = next_nonce;
                    continue;
                }
                if method == Method::CreatePermission {
                    permission_count += 1;
                } else if method == Method::ChannelBind {
                    channel_count += 1;
                }
                let response = Message {
                    header: Header {
                        class: Class::Success,
                        method,
                        transaction_id: verified.message().header.transaction_id,
                    },
                    attributes: if method == Method::Allocate {
                        vec![
                            Attribute::XorRelayedAddress("127.0.0.1:49000".parse().unwrap()),
                            Attribute::Lifetime(1),
                        ]
                    } else if method == Method::Refresh
                        && verified
                            .message()
                            .attributes
                            .iter()
                            .any(|attribute| matches!(attribute, Attribute::Lifetime(0)))
                    {
                        vec![Attribute::Lifetime(0)]
                    } else {
                        vec![Attribute::Lifetime(1)]
                    },
                };
                server
                    .send_to(
                        &wire::encode_with_integrity(&response, key.as_ref()).unwrap(),
                        source,
                    )
                    .await
                    .unwrap();
                if method == Method::ChannelBind {
                    let wrong_channel =
                        wire::encode_channel_data(0x4001, b"wrong-channel").unwrap();
                    server.send_to(&wrong_channel, source).await.unwrap();
                    let inbound = wire::encode_channel_data(0x4000, b"inbound").unwrap();
                    server.send_to(&inbound, source).await.unwrap();
                }
                if method == Method::Refresh
                    && verified
                        .message()
                        .attributes
                        .iter()
                        .any(|attribute| matches!(attribute, Attribute::Lifetime(0)))
                {
                    break true;
                }
            };
            (
                saw_refresh_zero,
                permission_count,
                channel_count,
                stale_methods.len(),
            )
        });
        let route = Arc::new(
            AuthenticatedTurnRoute::establish(TurnRouteConfig {
                server: server_addr,
                bind: "127.0.0.1:0".parse().unwrap(),
                username: b"alice".to_vec(),
                password,
                peer: peer_addr,
                channel: 0x4000,
                timeout: Duration::from_secs(2),
            })
            .await
            .unwrap(),
        );
        assert_eq!(route.generation(), 1);
        assert_eq!(
            route.local_addr().unwrap(),
            "127.0.0.1:49000".parse().unwrap()
        );
        assert_eq!(
            AsyncUdpSocket::local_addr(route.as_ref()).unwrap(),
            "127.0.0.1:49000".parse().unwrap()
        );
        let forged = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let control_addr = route.inner.socket.local_addr().unwrap();
        forged
            .send_to(
                &wire::encode_channel_data(0x4000, b"wrong-source").unwrap(),
                control_addr,
            )
            .await
            .unwrap();
        peer.send_to(
            &wire::encode_channel_data(0x4001, b"wrong-channel").unwrap(),
            control_addr,
        )
        .await
        .unwrap();
        let mut output = vec![0_u8; MAX_PAYLOAD];
        let transmit = Transmit {
            destination: peer_addr,
            ecn: None,
            contents: b"outbound",
            segment_size: None,
            src_ip: None,
        };
        route.try_send(&transmit).unwrap();
        assert!(route
            .try_send(&Transmit {
                destination: peer_addr,
                ecn: None,
                contents: b"x",
                segment_size: Some(1),
                src_ip: None,
            })
            .is_err());
        assert!(route
            .try_send(&Transmit {
                destination: peer_addr,
                ecn: None,
                contents: &vec![0_u8; MAX_PAYLOAD + 1],
                segment_size: None,
                src_ip: None,
            })
            .is_err());
        assert!(route
            .try_send(&Transmit {
                destination: peer_addr,
                ecn: None,
                contents: b"x",
                segment_size: None,
                src_ip: Some("127.0.0.1".parse().unwrap()),
            })
            .is_err());
        let mut metadata = [RecvMeta::default()];
        let received = time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|cx| {
                let mut slices = [IoSliceMut::new(&mut output)];
                route.poll_recv(cx, &mut slices, &mut metadata)
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received, 1);
        assert_eq!(&output[..metadata[0].len], b"inbound");
        assert_eq!(metadata[0].addr, peer_addr);
        route
            .try_send(&Transmit {
                destination: peer_addr,
                ecn: Some(quinn_udp::EcnCodepoint::Ect0),
                contents: b"ecn",
                segment_size: None,
                src_ip: None,
            })
            .expect("ECN metadata may be ignored like Quinn's fallback UDP adapter");
        time::sleep(Duration::from_millis(700)).await;
        assert!(route.generation() >= 2);
        route.shutdown().await.unwrap();
        assert!(route.try_send(&transmit).is_err());
        let (deallocated, permission_count, channel_count, stale_count) =
            server_task.await.unwrap();
        assert!(deallocated);
        assert!(permission_count >= 2);
        assert!(channel_count >= 2);
        assert_eq!(stale_count, 4);
    }

    #[tokio::test]
    async fn cancelled_establish_aborts_reader_and_releases_its_udp_port() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let task = tokio::spawn(AuthenticatedTurnRoute::establish(TurnRouteConfig {
            server: server_addr,
            bind: "127.0.0.1:0".parse().unwrap(),
            username: b"alice".to_vec(),
            password: b"0123456789abcdef-password".to_vec(),
            peer: peer.local_addr().unwrap(),
            channel: 0x4000,
            timeout: Duration::from_secs(10),
        }));
        let mut request = vec![0_u8; wire::MAX_DATAGRAM_BYTES];
        let (_, source) = time::timeout(Duration::from_secs(1), server.recv_from(&mut request))
            .await
            .unwrap()
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::task::yield_now().await;
        let rebound = UdpSocket::bind(source)
            .await
            .expect("cancelled establish detached its reader/socket");
        assert_eq!(rebound.local_addr().unwrap(), source);
    }

    #[tokio::test]
    async fn cancelled_request_removes_pending_response() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let inner = Arc::new(Inner {
            socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            server: server_addr,
            peer: "127.0.0.1:4000".parse().unwrap(),
            channel: 0x4000,
            relayed: Mutex::new("127.0.0.1:49000".parse().unwrap()),
            state: Mutex::new(LiveState {
                expiry: Instant::now() + Duration::from_secs(10),
                generation: 1,
                revoked: false,
            }),
            responses: Mutex::new(HashMap::new()),
            queue: Mutex::new(VecDeque::new()),
            queue_bytes: Mutex::new(0),
            queue_waker: Mutex::new(None),
            stop: watch::channel(false).0,
            credentials: Mutex::new(None),
            password: Zeroizing::new(Vec::new()),
            auth_lock: tokio::sync::Mutex::new(()),
            timeout: Duration::from_secs(10),
        });
        let request_id = [9_u8; 12];
        let request_inner = Arc::clone(&inner);
        let task = tokio::spawn(async move {
            request(
                &request_inner,
                wire::encode(&Message {
                    header: Header {
                        class: Class::Request,
                        method: Method::Allocate,
                        transaction_id: request_id,
                    },
                    attributes: vec![],
                })
                .unwrap(),
                request_id,
            )
            .await
        });
        let mut datagram = [0_u8; wire::MAX_DATAGRAM_BYTES];
        let _ = time::timeout(Duration::from_secs(1), server.recv_from(&mut datagram))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(inner.responses.lock().unwrap().len(), 1);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(inner.responses.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn request_honors_total_deadline_without_post_deadline_retransmit() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let inner = bare_inner(
            Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            server.local_addr().unwrap(),
            Duration::from_millis(40),
        );
        let id = [8_u8; 12];
        let request_inner = Arc::clone(&inner);
        let started = Instant::now();
        let task = tokio::spawn(async move {
            request(
                &request_inner,
                wire::encode(&Message {
                    header: Header {
                        class: Class::Request,
                        method: Method::Allocate,
                        transaction_id: id,
                    },
                    attributes: vec![],
                })
                .unwrap(),
                id,
            )
            .await
        });
        let mut datagram = [0_u8; wire::MAX_DATAGRAM_BYTES];
        let mut received = 0;
        while time::timeout(Duration::from_millis(80), server.recv_from(&mut datagram))
            .await
            .is_ok()
        {
            received += 1;
        }
        let result = task.await.unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(received, 1);
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[tokio::test]
    async fn authenticated_request_retries_one_signed_438_then_fails_closed() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let mut inner = bare_inner(Arc::clone(&client), server_addr, Duration::from_secs(2));
        let username = b"alice".to_vec();
        let old_realm = b"old.realm".to_vec();
        let old_nonce = b"old-nonce".to_vec();
        let password = b"0123456789abcdef-password".to_vec();
        Arc::get_mut(&mut inner).unwrap().password = Zeroizing::new(password.clone());
        *inner.credentials.lock().unwrap() = Some(RefreshCredentials {
            username: Zeroizing::new(username.clone()),
            realm: Zeroizing::new(old_realm.clone()),
            nonce: Zeroizing::new(old_nonce.clone()),
            key: wire::derive_long_term_key_sha256(&username, &old_realm, &password),
        });
        let reader = tokio::spawn(read_loop(Arc::clone(&inner)));
        let request_inner = Arc::clone(&inner);
        let request_task = tokio::spawn(async move {
            authenticated_request(
                &request_inner,
                Method::Refresh,
                vec![Attribute::Lifetime(1)],
            )
            .await
        });
        let mut datagram = [0_u8; wire::MAX_DATAGRAM_BYTES];
        let (length, source) = server.recv_from(&mut datagram).await.unwrap();
        let old_key = wire::derive_long_term_key_sha256(&username, &old_realm, &password);
        let first = wire::verify_integrity(&datagram[..length], old_key.as_ref()).unwrap();
        let new_realm = b"new.realm".to_vec();
        let new_nonce = b"new-nonce".to_vec();
        let stale = Message {
            header: Header {
                class: Class::Error,
                method: first.message().header.method,
                transaction_id: first.message().header.transaction_id,
            },
            attributes: vec![
                Attribute::ErrorCode {
                    code: 438,
                    reason: "Stale Nonce".into(),
                },
                Attribute::Realm(new_realm.clone()),
                Attribute::Nonce(new_nonce.clone()),
            ],
        };
        // Neither a forged MESSAGE-INTEGRITY nor an unsigned response may
        // consume the pending transaction.  The valid old-key response below
        // must still complete the same request.
        let forged = [0xa5_u8; 32];
        server
            .send_to(
                &wire::encode_with_integrity(&stale, &forged).unwrap(),
                source,
            )
            .await
            .unwrap();
        server
            .send_to(&wire::encode(&stale).unwrap(), source)
            .await
            .unwrap();
        server
            .send_to(
                &wire::encode_with_integrity(&stale, old_key.as_ref()).unwrap(),
                source,
            )
            .await
            .unwrap();
        let (length, source) = server.recv_from(&mut datagram).await.unwrap();
        let new_key = wire::derive_long_term_key_sha256(&username, &new_realm, &password);
        let retry = wire::verify_integrity(&datagram[..length], new_key.as_ref()).unwrap();
        assert_eq!(retry.message().header.method, Method::Refresh);
        assert_ne!(
            retry.message().header.transaction_id,
            first.message().header.transaction_id
        );
        let stale_again = Message {
            header: Header {
                class: Class::Error,
                method: retry.message().header.method,
                transaction_id: retry.message().header.transaction_id,
            },
            attributes: vec![
                Attribute::ErrorCode {
                    code: 438,
                    reason: "Stale Nonce".into(),
                },
                Attribute::Realm(new_realm),
                Attribute::Nonce(new_nonce),
            ],
        };
        server
            .send_to(
                &wire::encode_with_integrity(&stale_again, new_key.as_ref()).unwrap(),
                source,
            )
            .await
            .unwrap();
        assert!(request_task.await.unwrap().is_err());
        inner.stop_tasks();
        reader.abort();
    }
}
