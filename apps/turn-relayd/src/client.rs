use crate::{ClientConfig, ClientReport, TurnServiceError};
use latencydesk_turn_relay::wire::{self, Attribute, Class, Header, Message, Method};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use zeroize::Zeroizing;

const MAX_REQUESTS: usize = 4;
const RETRANSMIT: Duration = Duration::from_millis(200);

pub async fn run_client(config: ClientConfig) -> Result<ClientReport, TurnServiceError> {
    validate(&config)?;
    let ClientConfig {
        server,
        bind,
        username,
        password,
        peer,
        timeout,
        channel,
        send_payload,
        channel_payload,
    } = config;
    let username = Zeroizing::new(username);
    let password = Zeroizing::new(password);
    let send_payload = Zeroizing::new(send_payload);
    let channel_payload = Zeroizing::new(channel_payload);
    let socket = UdpSocket::bind(bind).await?;
    let deadline = tokio::time::Instant::now() + timeout;

    let challenge_transaction = random_transaction_id()?;
    let challenge_request = Zeroizing::new(wire::encode(&Message {
        header: Header {
            class: Class::Request,
            method: Method::Allocate,
            transaction_id: challenge_transaction,
        },
        attributes: vec![Attribute::RequestedTransport(17), Attribute::Lifetime(600)],
    })?);
    let challenge_bytes = request(
        &socket,
        server,
        &challenge_request,
        challenge_transaction,
        deadline,
    )
    .await
    .map_err(|error| stage(error, "challenge response timeout"))?;
    let challenge = wire::decode(&challenge_bytes)?;
    require_response(
        &challenge,
        Method::Allocate,
        Class::Error,
        challenge_transaction,
    )?;
    if error_code(&challenge) != Some(401) {
        return Err(TurnServiceError::Protocol(
            "initial Allocate was not challenged",
        ));
    }
    let realm = Zeroizing::new(required_bytes(&challenge, BytesKind::Realm)?.to_vec());
    let nonce = Zeroizing::new(required_bytes(&challenge, BytesKind::Nonce)?.to_vec());
    let key = wire::derive_long_term_key_sha256(&username, &realm, &password);

    let allocate_transaction = random_transaction_id()?;
    let allocate = signed_request(
        Method::Allocate,
        allocate_transaction,
        &username,
        &realm,
        &nonce,
        vec![Attribute::RequestedTransport(17), Attribute::Lifetime(600)],
        key.as_ref(),
    )?;
    let allocation_response = request(&socket, server, &allocate, allocate_transaction, deadline)
        .await
        .map_err(|error| stage(error, "Allocate response timeout"))?;
    let allocation = wire::verify_integrity(&allocation_response, key.as_ref())?;
    require_response(
        allocation.message(),
        Method::Allocate,
        Class::Success,
        allocate_transaction,
    )?;
    let relayed_address = allocation
        .message()
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            Attribute::XorRelayedAddress(address) => Some(*address),
            _ => None,
        })
        .ok_or(TurnServiceError::Protocol(
            "Allocate response omitted relay address",
        ))?;

    let permission_transaction = random_transaction_id()?;
    let permission = signed_request(
        Method::CreatePermission,
        permission_transaction,
        &username,
        &realm,
        &nonce,
        vec![Attribute::XorPeerAddress(peer)],
        key.as_ref(),
    )?;
    let permission_response = request(
        &socket,
        server,
        &permission,
        permission_transaction,
        deadline,
    )
    .await
    .map_err(|error| stage(error, "CreatePermission response timeout"))?;
    let permission_verified = wire::verify_integrity(&permission_response, key.as_ref())?;
    require_response(
        permission_verified.message(),
        Method::CreatePermission,
        Class::Success,
        permission_transaction,
    )?;

    let channel_transaction = random_transaction_id()?;
    let binding = signed_request(
        Method::ChannelBind,
        channel_transaction,
        &username,
        &realm,
        &nonce,
        vec![
            Attribute::ChannelNumber(channel),
            Attribute::XorPeerAddress(peer),
        ],
        key.as_ref(),
    )?;
    let binding_response = request(&socket, server, &binding, channel_transaction, deadline)
        .await
        .map_err(|error| stage(error, "ChannelBind response timeout"))?;
    let binding_verified = wire::verify_integrity(&binding_response, key.as_ref())?;
    require_response(
        binding_verified.message(),
        Method::ChannelBind,
        Class::Success,
        channel_transaction,
    )?;

    let send = Zeroizing::new(wire::encode(&Message {
        header: Header {
            class: Class::Indication,
            method: Method::Send,
            transaction_id: random_transaction_id()?,
        },
        attributes: vec![
            Attribute::XorPeerAddress(peer),
            Attribute::Data(send_payload.to_vec()),
        ],
    })?);
    socket.send_to(&send, server).await?;
    let send_echo = receive_channel_payload(&socket, server, channel, deadline)
        .await
        .map_err(|error| stage(error, "Send indication relay timeout"))?;
    let send_round_trip = send_echo.as_slice() == send_payload.as_slice();

    let channel_data = Zeroizing::new(wire::encode_channel_data(channel, &channel_payload)?);
    socket.send_to(&channel_data, server).await?;
    let channel_echo = receive_channel_payload(&socket, server, channel, deadline)
        .await
        .map_err(|error| stage(error, "ChannelData relay timeout"))?;
    let channel_round_trip = channel_echo.as_slice() == channel_payload.as_slice();

    let delete_transaction = random_transaction_id()?;
    let delete = signed_request(
        Method::Refresh,
        delete_transaction,
        &username,
        &realm,
        &nonce,
        vec![Attribute::Lifetime(0)],
        key.as_ref(),
    )?;
    let delete_response = request(&socket, server, &delete, delete_transaction, deadline)
        .await
        .map_err(|error| stage(error, "Refresh(0) response timeout"))?;
    let delete_verified = wire::verify_integrity(&delete_response, key.as_ref())?;
    require_response(
        delete_verified.message(),
        Method::Refresh,
        Class::Success,
        delete_transaction,
    )?;
    let deallocated = delete_verified
        .message()
        .attributes
        .iter()
        .any(|attribute| matches!(attribute, Attribute::Lifetime(0)));

    if !send_round_trip || !channel_round_trip || !deallocated {
        return Err(TurnServiceError::Protocol(
            "TURN evidence exchange incomplete",
        ));
    }
    Ok(ClientReport {
        challenge_authenticated: true,
        send_round_trip,
        channel_round_trip,
        deallocated,
        relayed_address,
    })
}

fn validate(config: &ClientConfig) -> Result<(), TurnServiceError> {
    if config.server.port() == 0
        || config.server.ip().is_unspecified()
        || config.server.ip().is_multicast()
        || config.bind.port() != 0
        || config.bind.ip().is_unspecified()
        || config.bind.is_ipv4() != config.server.is_ipv4()
        || config.peer.port() == 0
        || config.peer.is_ipv4() != config.server.is_ipv4()
        || config.username.is_empty()
        || config.username.len() > 512
        || config.password.len() < 16
        || config.password.len() > 512
        || config.timeout.is_zero()
        || config.timeout > Duration::from_secs(120)
        || !(wire::CHANNEL_MIN..=wire::CHANNEL_MAX).contains(&config.channel)
        || config.send_payload.len() > wire::MAX_DATAGRAM_BYTES / 2
        || config.channel_payload.len() > wire::MAX_DATAGRAM_BYTES / 2
    {
        return Err(TurnServiceError::InvalidConfig);
    }
    Ok(())
}

fn stage(error: TurnServiceError, timeout_message: &'static str) -> TurnServiceError {
    if matches!(error, TurnServiceError::Timeout) {
        TurnServiceError::Protocol(timeout_message)
    } else {
        error
    }
}

fn signed_request(
    method: Method,
    transaction_id: [u8; 12],
    username: &[u8],
    realm: &[u8],
    nonce: &[u8],
    mut attributes: Vec<Attribute>,
    key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, TurnServiceError> {
    let mut credentials = vec![
        Attribute::Username(username.to_vec()),
        Attribute::Realm(realm.to_vec()),
        Attribute::Nonce(nonce.to_vec()),
    ];
    credentials.append(&mut attributes);
    Ok(Zeroizing::new(wire::encode_with_integrity(
        &Message {
            header: Header {
                class: Class::Request,
                method,
                transaction_id,
            },
            attributes: credentials,
        },
        key,
    )?))
}

async fn request(
    socket: &UdpSocket,
    server: SocketAddr,
    encoded: &[u8],
    transaction_id: [u8; 12],
    deadline: tokio::time::Instant,
) -> Result<Zeroizing<Vec<u8>>, TurnServiceError> {
    let mut buffer = Zeroizing::new(vec![0_u8; wire::MAX_DATAGRAM_BYTES + 1]);
    for _ in 0..MAX_REQUESTS {
        socket.send_to(encoded, server).await?;
        let attempt_deadline = (tokio::time::Instant::now() + RETRANSMIT).min(deadline);
        loop {
            let received =
                tokio::time::timeout_at(attempt_deadline, socket.recv_from(&mut buffer)).await;
            let (length, source) = match received {
                Ok(Ok(value)) => value,
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => break,
            };
            if source != server || length > wire::MAX_DATAGRAM_BYTES {
                continue;
            }
            let Ok(message) = wire::decode(&buffer[..length]) else {
                continue;
            };
            if message.header.transaction_id == transaction_id {
                return Ok(Zeroizing::new(buffer[..length].to_vec()));
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(TurnServiceError::Timeout);
        }
    }
    Err(TurnServiceError::Timeout)
}

async fn receive_channel_payload(
    socket: &UdpSocket,
    server: SocketAddr,
    expected_channel: u16,
    deadline: tokio::time::Instant,
) -> Result<Zeroizing<Vec<u8>>, TurnServiceError> {
    let mut buffer = Zeroizing::new(vec![0_u8; wire::MAX_DATAGRAM_BYTES + 1]);
    loop {
        let (length, source) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer))
            .await
            .map_err(|_| TurnServiceError::Timeout)??;
        if source != server || length > wire::MAX_DATAGRAM_BYTES {
            continue;
        }
        if let Ok((channel, payload)) = wire::decode_channel_data(&buffer[..length]) {
            if channel == expected_channel {
                return Ok(Zeroizing::new(payload.to_vec()));
            }
        }
    }
}

fn require_response(
    message: &Message,
    method: Method,
    class: Class,
    transaction_id: [u8; 12],
) -> Result<(), TurnServiceError> {
    if message.header.class == Class::Error && class != Class::Error {
        return Err(TurnServiceError::ResponseCode(
            error_code(message).unwrap_or(400),
        ));
    }
    if message.header.method != method
        || message.header.class != class
        || message.header.transaction_id != transaction_id
    {
        return Err(TurnServiceError::Protocol(
            "TURN response transcript mismatch",
        ));
    }
    Ok(())
}

fn error_code(message: &Message) -> Option<u16> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            Attribute::ErrorCode { code, .. } => Some(*code),
            _ => None,
        })
}

enum BytesKind {
    Realm,
    Nonce,
}

fn required_bytes(message: &Message, kind: BytesKind) -> Result<&[u8], TurnServiceError> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match (&kind, attribute) {
            (BytesKind::Realm, Attribute::Realm(value))
            | (BytesKind::Nonce, Attribute::Nonce(value)) => Some(value.as_slice()),
            _ => None,
        })
        .ok_or(TurnServiceError::Protocol("challenge credential missing"))
}

fn random_transaction_id() -> Result<[u8; 12], TurnServiceError> {
    let mut transaction_id = [0_u8; 12];
    getrandom::getrandom(&mut transaction_id).map_err(|_| TurnServiceError::Randomness)?;
    if transaction_id == [0; 12] {
        transaction_id[0] = 1;
    }
    Ok(transaction_id)
}
