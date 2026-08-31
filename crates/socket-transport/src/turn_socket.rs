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
use zeroize::Zeroizing;

const ALLOCATION_LIFETIME: u64 = 600;
const MAX_QUEUE: usize = 64;
const MAX_PAYLOAD: usize = wire::MAX_DATAGRAM_BYTES - 4;
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
    responses: Mutex<HashMap<[u8; 12], oneshot::Sender<Vec<u8>>>>,
    queue: Mutex<VecDeque<Vec<u8>>>,
    queue_waker: Mutex<Option<Waker>>,
    stop: watch::Sender<bool>,
    credentials: Mutex<Option<RefreshCredentials>>,
    timeout: Duration,
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

impl AuthenticatedTurnRoute {
    /// Establish an authenticated allocation and bind exactly one peer and
    /// channel. This is the only public construction path.
    pub async fn establish(config: TurnRouteConfig) -> io::Result<Self> {
        validate_config(&config)?;
        let socket = Arc::new(UdpSocket::bind(config.bind).await?);
        let (stop, _) = watch::channel(false);
        let username = Zeroizing::new(config.username);
        let password = Zeroizing::new(config.password);
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
            queue_waker: Mutex::new(None),
            stop,
            credentials: Mutex::new(None),
            timeout: config.timeout,
        });
        let reader_inner = inner.clone();
        let reader = tokio::spawn(read_loop(reader_inner));
        let guard = EstablishGuard {
            inner: Arc::clone(&inner),
            reader: Some(reader),
            armed: true,
        };

        let (realm, nonce, key, relayed, expiry) =
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
        *inner
            .credentials
            .lock()
            .expect("credentials mutex poisoned") = Some(RefreshCredentials {
            username,
            realm,
            nonce,
            key,
        });

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
        if let Some(payload) = queue.pop_front() {
            if payload.len() > bufs[0].len() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "receive buffer too small",
                )));
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
                    let mut queue = inner.queue.lock().expect("queue mutex poisoned");
                    if queue.len() < MAX_QUEUE { queue.push_back(payload.to_vec()); }
                    drop(queue);
                    if let Some(waker) = inner.queue_waker.lock().expect("queue waker poisoned").take() { waker.wake(); }
                    continue;
                }
                let Ok(message) = wire::decode(datagram) else { continue; };
                if !matches!(message.header.class, Class::Success | Class::Error) { continue; }
                if let Some(sender) = inner.responses.lock().expect("response mutex poisoned").remove(&message.header.transaction_id) { let _ = sender.send(datagram.to_vec()); }
            }
        }
    }
}

async fn establish_transcript(
    inner: &Arc<Inner>,
    server: SocketAddr,
    peer: SocketAddr,
    channel: u16,
    username: &[u8],
    password: &[u8],
) -> io::Result<(
    Zeroizing<Vec<u8>>,
    Zeroizing<Vec<u8>>,
    Zeroizing<[u8; 32]>,
    SocketAddr,
    Instant,
)> {
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

    let allocation_id = transaction_id()?;
    let allocation = signed_request(
        Method::Allocate,
        allocation_id,
        username,
        &realm,
        &nonce,
        vec![
            Attribute::RequestedTransport(17),
            Attribute::Lifetime(ALLOCATION_LIFETIME as u32),
        ],
        key.as_ref(),
    )?;
    let allocation = wire::verify_integrity(
        &request(inner, allocation, allocation_id).await?,
        key.as_ref(),
    )
    .map_err(wire_error)?;
    require_success(allocation.message(), Method::Allocate, allocation_id)?;
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

    let permission_id = transaction_id()?;
    let permission = signed_request(
        Method::CreatePermission,
        permission_id,
        username,
        &realm,
        &nonce,
        vec![Attribute::XorPeerAddress(peer)],
        key.as_ref(),
    )?;
    let permission = wire::verify_integrity(
        &request(inner, permission, permission_id).await?,
        key.as_ref(),
    )
    .map_err(wire_error)?;
    require_success(
        permission.message(),
        Method::CreatePermission,
        permission_id,
    )?;
    let binding_id = transaction_id()?;
    let binding = signed_request(
        Method::ChannelBind,
        binding_id,
        username,
        &realm,
        &nonce,
        vec![
            Attribute::ChannelNumber(channel),
            Attribute::XorPeerAddress(peer),
        ],
        key.as_ref(),
    )?;
    let binding = wire::verify_integrity(&request(inner, binding, binding_id).await?, key.as_ref())
        .map_err(wire_error)?;
    require_success(binding.message(), Method::ChannelBind, binding_id)?;
    Ok((
        realm,
        nonce,
        key,
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
    let (username, realm, nonce, key) = cloned_credentials(inner)?;
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
        let id = transaction_id()?;
        let encoded = signed_request(
            method,
            id,
            &username,
            &realm,
            &nonce,
            attributes,
            key.as_ref(),
        )?;
        let response = wire::verify_integrity(&request(inner, encoded, id).await?, key.as_ref())
            .map_err(wire_error)?;
        require_success(response.message(), method, id)?;
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
    let (username, realm, nonce, key) = cloned_credentials(inner)?;
    let id = transaction_id()?;
    let encoded = signed_request(
        Method::Refresh,
        id,
        &username,
        &realm,
        &nonce,
        vec![Attribute::Lifetime(lifetime)],
        key.as_ref(),
    )?;
    let response = wire::verify_integrity(&request(inner, encoded, id).await?, key.as_ref())
        .map_err(wire_error)?;
    require_success(response.message(), Method::Refresh, id)?;
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

async fn request(inner: &Arc<Inner>, encoded: Vec<u8>, id: [u8; 12]) -> io::Result<Vec<u8>> {
    inner.ensure_live()?;
    let (sender, receiver) = oneshot::channel();
    inner
        .responses
        .lock()
        .expect("response mutex poisoned")
        .insert(id, sender);
    let deadline = Instant::now() + inner.timeout;
    let mut receiver = receiver;
    for _ in 0..4 {
        if let Err(error) = inner.socket.send_to(&encoded, inner.server).await {
            inner
                .responses
                .lock()
                .expect("response mutex poisoned")
                .remove(&id);
            return Err(error);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let attempt = remaining.min(Duration::from_millis(200));
        match time::timeout(attempt, &mut receiver).await {
            Ok(Ok(response)) => return Ok(response),
            Ok(Err(_)) => break,
            Err(_) => {}
        }
    }
    inner
        .responses
        .lock()
        .expect("response mutex poisoned")
        .remove(&id);
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
    if relayed.port() == 0 || unusable(relayed) || relayed.is_ipv4() != server.is_ipv4() {
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
                let key = wire::derive_long_term_key_sha256(b"alice", &realm, &server_password);
                let verified = wire::verify_integrity(&datagram[..length], key.as_ref()).unwrap();
                let method = verified.message().header.method;
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
            (saw_refresh_zero, permission_count, channel_count)
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
        let (deallocated, permission_count, channel_count) = server_task.await.unwrap();
        assert!(deallocated);
        assert!(permission_count >= 2);
        assert!(channel_count >= 2);
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
}
