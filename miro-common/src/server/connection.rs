use std::{
    borrow::Cow,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::{BufMut, Bytes};
use http::{Method, Request, Response, Version};
use s2n_quic::{
    connection::{BidirectionalStreamAcceptor, Handle},
    provider::datagram::default::Receiver,
};
use s2n_quic_h3::h3;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{
    datagram::{
        DatagramPacket, DatagramSender, DatagramSessionManager, QuicDatagramError,
        MAX_DATAGRAM_CHANNEL_CAPACITY,
    },
    utils::{transform_connection_error, AsyncReadStreamExt, BoxFuture, BufExt, BufMutExt},
    ClientHandshake, DatagramFrame, DatagramSessionId, ProxyAddress, ServerHandshake,
    ServerMaxReceiveRate, TcpRequest, TcpResponse, AUTH_RESPONSE_PADDING, CLIENT_TCP_REQUEST_ID,
    HANDSHAKE_HEADER_AUTH, HANDSHAKE_HEADER_CC_RX, HANDSHAKE_HEADER_PADDING, HANDSHAKE_HEADER_UDP,
    HANDSHAKE_HOST, HANDSHAKE_PATH, HANDSHAKE_STATUS_OK, SERVER_TCP_RESPONSE_STATUS_OK,
    TCP_RESPONSE_PADDING,
};

use super::{
    Authenticator, ConnectionConfig, Error, OutboundDatagramProvider, OutboundStreamProvider,
};

#[derive(Debug)]
pub struct Connection<Auth, OutboundStream, OutboundDatagram> {
    conn: s2n_quic::Connection,
    config: ConnectionConfig<Auth, OutboundStream, OutboundDatagram>,
    session: DatagramSessionManager,
}

impl<Auth, OutboundStream, OutboundDatagram> Connection<Auth, OutboundStream, OutboundDatagram> {
    pub(crate) fn new(
        conn: s2n_quic::Connection,
        config: ConnectionConfig<Auth, OutboundStream, OutboundDatagram>,
    ) -> Self {
        let idle_timeout = config.udp_idle_timeout;
        Self {
            conn,
            config,
            session: DatagramSessionManager::new(idle_timeout),
        }
    }
}

impl<
        Auth: Authenticator,
        OutboundStream: OutboundStreamProvider,
        OutboundDatagram: OutboundDatagramProvider,
    > Connection<Auth, OutboundStream, OutboundDatagram>
{
    #[tracing::instrument(level = "info", skip(self), fields(conn.ip = ?self.conn.remote_addr(), conn.id = self.conn.id()))]
    pub async fn process(self) -> Result<(), Error> {
        let conn = self.conn;
        let local_addr = conn.local_addr()?;
        let remote_addr = conn.remote_addr()?;
        tracing::info!("Processing connection");
        let mut h3_conn: h3::server::Connection<s2n_quic_h3::Connection, Bytes> =
            h3::server::Connection::new(s2n_quic_h3::Connection::new(conn)).await?;
        match h3_conn.accept().await {
            Ok(Some((request, stream))) => {
                tracing::info!("Stream ID: {:?}", stream.id());
                tracing::debug!("Received request: {:?}", request);

                let client_handshake = match client_handshake(request.clone()) {
                    Ok(handshake) => handshake,
                    Err(e) => {
                        tracing::warn!("Client handshake failed: {:?}, serve the connection as a HTTP connection.", e);
                        return serve_masquerading_http(request, stream, h3_conn).await;
                    }
                };
                if !self
                    .config
                    .auth
                    .authenticate(&client_handshake.auth, remote_addr, local_addr)
                    .await?
                {
                    tracing::warn!(
                        "Authentication failed, serve the connection as a HTTP connection."
                    );
                    return serve_masquerading_http(request, stream, h3_conn).await;
                }
                tracing::debug!("Client authentication succeeded: {:?}", client_handshake);
                server_handshake(stream, self.config.udp, self.config.cc_rx).await?;
                tracing::info!(
                    "Handshake completed, serve the connection as a Hysteria connection."
                );
                let conn = &mut h3_conn.inner.conn.conn;
                let bidi_acceptor = &mut h3_conn.inner.conn.bidi_acceptor;
                let datagram_process = async move {
                    if !self.config.udp {
                        tracing::info!("UDP is disabled, skip the UDP transport process.");
                        return Ok::<(), Error>(());
                    }
                    loop {
                        if !Self::receive_datagram(
                            conn.clone(),
                            self.session.clone(),
                            self.config.udp_idle_timeout,
                            self.config.datagram_outbound.clone(),
                        )
                        .await?
                        {
                            tracing::info!("Connection closed");
                            return Ok(());
                        }
                    }
                };
                let stream_process = async move {
                    loop {
                        if !Self::receive_stream(bidi_acceptor, self.config.stream_outbound.clone())
                            .await?
                        {
                            tracing::debug!("Connection closed");
                            return Ok(());
                        }
                    }
                };
                tokio::try_join!(datagram_process, stream_process)?;
            }
            Ok(None) => {
                tracing::debug!("No request received");
            }
            Err(e) => {
                tracing::warn!("Error accepting request: {}", e);
                return Err(Error::from(e))?;
            }
        }
        Ok(())
    }

    /// Returns `true` if the connection is still alive, `false` if the connection is closed.
    async fn receive_datagram(
        conn: Handle,
        session_cache: DatagramSessionManager,
        idle_timeout: Duration,
        out_datagram_provider: Arc<OutboundDatagram>,
    ) -> Result<bool, Error> {
        let datagram = ReceiveDatagram { conn: &conn }.await;
        let datagram = match datagram {
            Ok(datagram) => datagram,
            Err(Error::QuicConnectionError(e)) => {
                if let Some(err) = transform_connection_error(e) {
                    return Err(err)?;
                } else {
                    return Ok(false);
                }
            }
            Err(e) => return Err(e),
        };
        let session_cache = session_cache.clone();
        tokio::spawn(async move {
            if let Err(e) = process_udp_message(
                session_cache,
                conn,
                datagram,
                idle_timeout,
                out_datagram_provider.as_ref(),
            )
            .await
            {
                tracing::warn!("Error processing UDP message: {}", e);
            }
        });
        Ok(true)
    }

    /// Returns `true` if the connection is still alive, `false` if the connection is closed.
    async fn receive_stream(
        acceptor: &mut BidirectionalStreamAcceptor,
        stream_outbound: Arc<OutboundStream>,
    ) -> Result<bool, Error> {
        match acceptor.accept_bidirectional_stream().await {
            Ok(Some(stream)) => {
                let (recv, send) = stream.split();
                tokio::spawn(async move {
                    if let Err(e) =
                        process_tcp_request_message(recv, send, stream_outbound.as_ref()).await
                    {
                        tracing::warn!("Error processing TCP request: {}", e);
                    }
                });
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(e) => {
                if let Some(err) = transform_connection_error(e) {
                    Err(err)?
                } else {
                    Ok(false)
                }
            }
        }
    }
}

struct ReceiveDatagram<'a> {
    conn: &'a Handle,
}

impl Future for ReceiveDatagram<'_> {
    type Output = Result<Bytes, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let datagram = this
            .conn
            .datagram_mut(|receiver: &mut Receiver| receiver.poll_recv_datagram(cx));
        let datagram = match datagram {
            Ok(poll) => poll,
            Err(e) => return Poll::Ready(Err(e)?),
        };

        match datagram {
            Poll::Ready(Ok(datagram)) => Poll::Ready(Ok(datagram)),
            Poll::Ready(Err(
                s2n_quic::provider::datagram::default::DatagramError::ConnectionError {
                    error, ..
                },
            )) => Poll::Ready(Err(Error::QuicConnectionError(error))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(QuicDatagramError::S2nQuicDatagramError(
                e.to_string().into(),
            ))?),
            Poll::Pending => Poll::Pending,
        }
    }
}

type ClientHandshakeError = Cow<'static, str>;

fn client_handshake<T>(request: Request<T>) -> Result<ClientHandshake, ClientHandshakeError> {
    let (parts, _) = request.into_parts();
    if parts.method != Method::POST {
        return Err(format!("Invalid method: {}", parts.method).into());
    }
    if parts.uri.host() != Some(HANDSHAKE_HOST) {
        return Err(format!("Invalid host: {:?}", parts.uri.host()).into());
    }
    if parts.uri.path() != HANDSHAKE_PATH {
        return Err(format!("Invalid path: {:?}", parts.uri.path()).into());
    }
    let headers = parts.headers;
    let auth = headers
        .get(HANDSHAKE_HEADER_AUTH)
        .ok_or_else(|| Cow::from("Missing Hysteria-Auth header"))?;
    let auth = auth
        .to_str()
        .map_err(|_| Cow::from("Invalid Hysteria-Auth header"))?;
    let cc_rx = headers
        .get(HANDSHAKE_HEADER_CC_RX)
        .ok_or_else(|| Cow::from("Missing Hysteria-CC-RX header"))?;
    let cc_rx_error: ClientHandshakeError = "Invalid Hysteria-CC-RX header".into();
    let cc_rx: u32 = cc_rx
        .to_str()
        .map_err(|_| cc_rx_error.clone())
        .and_then(|v| v.parse().map_err(|_| cc_rx_error))?;
    let padding = headers
        .get(HANDSHAKE_HEADER_PADDING)
        .ok_or_else(|| Cow::from("Missing Hysteria-Padding header"))?;
    padding
        .to_str()
        .map_err(|_| Cow::from("Invalid Hysteria-Padding header"))?;
    Ok(ClientHandshake {
        auth: auth.into(),
        cc_rx,
    })
}

fn build_server_handshake(response: ServerHandshake) -> Response<()> {
    let builder = Response::builder()
        .status(HANDSHAKE_STATUS_OK)
        .version(Version::HTTP_3)
        .header(HANDSHAKE_HEADER_UDP, response.udp.to_string())
        .header(HANDSHAKE_HEADER_CC_RX, response.cc_rx.to_string())
        .header(HANDSHAKE_HEADER_PADDING, AUTH_RESPONSE_PADDING.generate());
    builder
        .body(())
        .expect("Failed to build the server handshake response.")
}

#[tracing::instrument(level = "debug", skip(stream, connection))]
async fn serve_masquerading_http<S: h3::quic::SendStream<B>, B: bytes::Buf>(
    _request: Request<()>,
    stream: h3::server::RequestStream<S, B>,
    mut connection: h3::server::Connection<s2n_quic_h3::Connection, B>,
) -> Result<(), Error> {
    send_404(stream).await?;
    while let Some((request, stream)) = connection.accept().await? {
        tracing::debug!("Received request: {:?}", request);
        send_404(stream).await?;
    }
    Ok(())
}

async fn send_404<S: h3::quic::SendStream<B>, B: bytes::Buf>(
    mut stream: h3::server::RequestStream<S, B>,
) -> Result<(), Error> {
    let response = Response::builder()
        .status(404)
        .version(Version::HTTP_3)
        .body(())
        .expect("Failed to build the masquerading 404 response.");
    stream.send_response(response).await?;
    stream.finish().await?;
    Ok(())
}

#[tracing::instrument(level = "debug", skip(stream))]
async fn server_handshake<S: h3::quic::SendStream<B>, B: bytes::Buf>(
    mut stream: h3::server::RequestStream<S, B>,
    udp_enabled: bool,
    cc_rx: ServerMaxReceiveRate,
) -> Result<(), Error> {
    let response = ServerHandshake {
        udp: udp_enabled,
        cc_rx,
    };
    let response = build_server_handshake(response);
    stream.send_response(response).await?;
    stream.finish().await?;
    Ok(())
}

#[tracing::instrument(level = "debug", skip(recv_stream, send_stream, stream_outbound))]
async fn process_tcp_request_message(
    mut recv_stream: impl AsyncRead + Unpin,
    mut send_stream: impl AsyncWrite + Unpin,
    stream_outbound: &impl OutboundStreamProvider,
) -> Result<(), Error> {
    let request = read_tcp_request_message(&mut recv_stream).await?;
    tracing::debug!("Received TCP request: {:?}", request);
    let response = TcpResponse {
        status: SERVER_TCP_RESPONSE_STATUS_OK,
        message: "Miro".into(),
    };
    send_tcp_response_message(&mut send_stream, response).await?;
    let (mut outbound_read, mut outbound_write) = stream_outbound.direct(&request.address).await?;
    tokio::try_join!(
        tokio::io::copy(&mut recv_stream, &mut outbound_write),
        tokio::io::copy(&mut outbound_read, &mut send_stream)
    )?;
    Ok(())
}

async fn read_tcp_request_message(
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<TcpRequest, Error> {
    let status = stream.read_varint().await?;
    if status != CLIENT_TCP_REQUEST_ID.as_u64() {
        return Err(Error::ParseError(
            format!("Invalid request ID: {}", status).into(),
        ))?;
    }
    let address = stream.read_proxy_address().await?;
    stream.read_padding().await?;
    Ok(TcpRequest { address })
}

async fn send_tcp_response_message(
    stream: &mut (impl AsyncWrite + Unpin),
    response: TcpResponse,
) -> Result<(), Error> {
    tracing::debug!("Sending TCP response: {:?}", response);
    let mut buf = bytes::BytesMut::with_capacity(2048);
    buf.put_u8(response.status);
    let message = response.message.as_bytes();
    buf.put_variable_slice(message)?;
    buf.put_padding(TCP_RESPONSE_PADDING)?;
    stream
        .write_all(&buf)
        .await
        .map_err(|e| Error::from(Arc::new(e)))
}

#[tracing::instrument(level = "debug", skip(cache, message, out_datagram_provider))]
async fn process_udp_message(
    cache: DatagramSessionManager,
    conn: s2n_quic::connection::Handle,
    message: Bytes,
    idle_timeout: Duration,
    out_datagram_provider: &impl OutboundDatagramProvider,
) -> Result<(), Error> {
    let frame = read_datagram_frame(message)?;
    if let Some(_data) = cache
        .insert_and_try_collect(
            frame.session_id,
            frame.packet_id,
            frame.frame_id,
            frame.payload.clone(),
            frame.frame_count,
        )
        .await
    {
        tracing::info!(
            "Received all frames for session_id: {}, packet_id: {}",
            frame.session_id,
            frame.packet_id
        );
        let create_sender_and_transport = async {
            let (sender, receiver) = tokio::sync::mpsc::channel(MAX_DATAGRAM_CHANNEL_CAPACITY);
            crate_udp_and_transport(
                conn,
                receiver,
                frame.session_id,
                &frame.address,
                idle_timeout,
                cache.get_session_invalidate_fn(),
                out_datagram_provider,
            )
            .await?;
            Ok(sender)
        };
        let sender = cache
            .get_sender(frame.session_id, create_sender_and_transport)
            .await
            .map_err(|e| Error::clone(&e))?;
        if let Err(e) = sender
            .send(DatagramPacket {
                session_id: frame.session_id,
                payload: frame.payload,
                address: frame.address,
            })
            .await
        {
            tracing::error!(
                session_id = frame.session_id,
                "Error transport Hysteria datagram packet in channel: {}, drop the session",
                e
            );
            cache.get_session_invalidate_fn()(frame.session_id).await;
        }
    }
    Ok(())
}

fn read_datagram_frame(mut message: Bytes) -> Result<DatagramFrame, Error> {
    let session_id = message.read_u32()?;
    let packet_id = message.read_u16()?;
    let frame_id = message.read_u8()?;
    let frame_count = message.read_u8()?;
    let address = message.read_proxy_address()?;
    Ok(DatagramFrame {
        session_id,
        packet_id,
        frame_id,
        frame_count,
        address,
        payload: message,
    })
}

async fn crate_udp_and_transport(
    connection: s2n_quic::connection::Handle,
    mut receiver: tokio::sync::mpsc::Receiver<DatagramPacket>,
    session_id: DatagramSessionId,
    addr: &ProxyAddress,
    idle_timeout: Duration,
    invalidate_fn: impl FnOnce(DatagramSessionId) -> BoxFuture<()> + Send + 'static,
    out_datagram_provider: &impl OutboundDatagramProvider,
) -> Result<(), Error> {
    use crate::server::outbound::DatagramSocket;
    let addr = addr.resolve().await?;
    let local_addr = if addr.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    };
    let udp = out_datagram_provider.direct(local_addr).await?;
    tokio::spawn(async move {
        let result = async move {
            let packet_sender = Arc::new(DatagramSender::new(connection));
            tracing::info!(session_id = session_id, "Starting UDP packet transport");
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(idle_timeout) => {
                        return Ok::<(), Error>(());
                    }
                    Some(packet) = receiver.recv() => {
                        let udp = udp.clone();
                        tokio::spawn(async move{
                            tracing::debug!(session_id = session_id, "Transport the Hysteria packet as a UDP packet: {:?}", packet);
                            if let Err(e) = udp.send_to_proxy_address(packet.payload, packet.address).await {
                                tracing::warn!(session_id = packet.session_id, "Error sending UDP packet: {}", e);
                            }
                        });
                    }
                    recv_data = udp.recv_from() => {
                        let (data, addr) = recv_data?;
                        let packet = DatagramPacket {
                            session_id,
                            payload: data,
                            address: ProxyAddress::new(addr.to_string()),
                        };
                        let packet_sender = packet_sender.clone();
                        tokio::spawn(async move {
                            tracing::debug!(session_id = session_id, "Transport the UDP packet as Hysteria packet(s): {:?}", packet);
                            if let Err(e) = packet_sender.send(packet) {
                                tracing::warn!("Error sending Hysteria datagram packet: {}", e);
                            }
                        });
                    }
                    else => return Ok(())
                }
            }
        };
        if let Err(e) = result.await {
            tracing::warn!(session_id = session_id, "Error sending UDP packet: {}", e);
        } else {
            tracing::info!(session_id = session_id, "Finished UDP packet transport");
        }
        invalidate_fn(session_id).await;
    });
    Ok(())
}

#[cfg(test)]
mod tests {

    mod client_handshake_tests {

        use crate::{
            server::connection::client_handshake, HANDSHAKE_HEADER_AUTH, HANDSHAKE_HEADER_CC_RX,
            HANDSHAKE_HEADER_PADDING,
        };
        use http::Method;
        use http::Request;

        #[test]
        fn test_client_handshake() {
            let request = Request::builder()
                .method(Method::POST)
                .uri("http://hysteria:8080/auth")
                .header(HANDSHAKE_HEADER_AUTH, "Hello")
                .header(HANDSHAKE_HEADER_CC_RX, "10")
                .header(HANDSHAKE_HEADER_PADDING, "Hello")
                .body(())
                .unwrap();
            let handshake = client_handshake(request).unwrap();
            assert_eq!(handshake.auth, "Hello");
            assert_eq!(handshake.cc_rx, 10);
        }

        #[test]
        fn test_client_handshake_invalid_method() {
            let request = Request::builder()
                .method(Method::GET)
                .uri("http://hysteria:8080/auth")
                .header(HANDSHAKE_HEADER_AUTH, "Hello")
                .header(HANDSHAKE_HEADER_CC_RX, "10")
                .header(HANDSHAKE_HEADER_PADDING, "Hello")
                .body(())
                .unwrap();
            let handshake = client_handshake(request);
            assert!(matches!(handshake, Err(e) if e == "Invalid method: GET"));
        }

        #[test]
        fn test_client_handshake_invalid_host() {
            let request = Request::builder()
                .method(Method::POST)
                .uri("http://localhost:8080/auth")
                .header(HANDSHAKE_HEADER_AUTH, "Hello")
                .header(HANDSHAKE_HEADER_CC_RX, "10")
                .header(HANDSHAKE_HEADER_PADDING, "Hello")
                .body(())
                .unwrap();
            let handshake = client_handshake(request);
            assert!(matches!(handshake, Err(e) if e == "Invalid host: Some(\"localhost\")"));
        }

        #[test]
        fn test_client_handshake_invalid_path() {
            let request = Request::builder()
                .method(Method::POST)
                .uri("http://hysteria:8080/handshake/invalid")
                .header(HANDSHAKE_HEADER_AUTH, "Hello")
                .header(HANDSHAKE_HEADER_CC_RX, "10")
                .header(HANDSHAKE_HEADER_PADDING, "Hello")
                .body(())
                .unwrap();
            let handshake = client_handshake(request);
            assert!(
                matches!(handshake, Err(e) if e.starts_with("Invalid path: \"/handshake/invalid\""))
            );
        }
    }

    mod server_handshake_tests {
        use crate::{
            server::connection::build_server_handshake, ServerHandshake, HANDSHAKE_HEADER_CC_RX,
            HANDSHAKE_HEADER_UDP, HANDSHAKE_STATUS_OK,
        };

        #[test]
        fn test_server_handshake() {
            let response = ServerHandshake {
                udp: true,
                cc_rx: crate::ServerMaxReceiveRate::Auto,
            };
            let response = build_server_handshake(response);
            assert_eq!(response.status(), HANDSHAKE_STATUS_OK);
            assert_eq!(
                response.headers().get(HANDSHAKE_HEADER_UDP).unwrap(),
                "true"
            );
            assert_eq!(
                response.headers().get(HANDSHAKE_HEADER_CC_RX).unwrap(),
                "auto"
            );
        }

        #[test]
        fn test_server_handshake_udp() {
            let response = ServerHandshake {
                udp: false,
                cc_rx: crate::ServerMaxReceiveRate::Auto,
            };
            let response = build_server_handshake(response);
            assert_eq!(response.status(), HANDSHAKE_STATUS_OK);
            assert_eq!(
                response.headers().get(HANDSHAKE_HEADER_UDP).unwrap(),
                "false"
            );
            assert_eq!(
                response.headers().get(HANDSHAKE_HEADER_CC_RX).unwrap(),
                "auto"
            );
        }

        #[test]
        fn test_server_handshake_cc_rx() {
            let response = ServerHandshake {
                udp: true,
                cc_rx: crate::ServerMaxReceiveRate::Specified(10),
            };
            let response = build_server_handshake(response);
            assert_eq!(response.status(), HANDSHAKE_STATUS_OK);
            assert_eq!(
                response.headers().get(HANDSHAKE_HEADER_UDP).unwrap(),
                "true"
            );
            assert_eq!(
                response.headers().get(HANDSHAKE_HEADER_CC_RX).unwrap(),
                "10"
            );
        }
    }

    mod read_tcp_request_message_tests {
        use std::io::Cursor;

        use crate::VarInt;

        use crate::{
            server::connection::read_tcp_request_message, utils::BufMutExt, CLIENT_TCP_REQUEST_ID,
            TCP_REQUEST_PADDING,
        };

        #[tokio::test]
        async fn test_read_tcp_request_message() {
            let mut buf = bytes::BytesMut::new();
            buf.put_varint(CLIENT_TCP_REQUEST_ID);
            buf.put_variable_slice(b"test.cc:80").unwrap();
            buf.put_padding(TCP_REQUEST_PADDING).unwrap();
            let mut stream = Cursor::new(buf.freeze());
            let request = read_tcp_request_message(&mut stream).await.unwrap();
            assert_eq!(request.address, "test.cc:80".into());
        }

        #[tokio::test]
        async fn test_read_tcp_request_message_invalid_request_id() {
            let mut buf = bytes::BytesMut::new();
            buf.put_varint(VarInt::from_u32(0));
            buf.put_variable_slice(b"test.cc:80\xFF").unwrap();
            buf.put_padding(TCP_REQUEST_PADDING).unwrap();
            let mut stream = Cursor::new(buf.freeze());
            let request = read_tcp_request_message(&mut stream).await;
            assert!(
                matches!(request, Err(crate::Error::ParseError(e)) if e == "Invalid request ID: 0")
            );
        }

        #[tokio::test]
        async fn test_read_tcp_request_message_invalid_address_length() {
            let mut buf = bytes::BytesMut::new();
            buf.put_varint(CLIENT_TCP_REQUEST_ID);
            buf.put_varint(VarInt::from_u32(0));
            buf.put_padding(TCP_REQUEST_PADDING).unwrap();
            let mut stream = Cursor::new(buf.freeze());
            let request = read_tcp_request_message(&mut stream).await;
            assert!(
                matches!(request, Err(crate::Error::ParseError(e)) if e == "Invalid address length")
            );
        }

        #[tokio::test]
        async fn test_read_tcp_request_message_invalid_address() {
            let mut buf = bytes::BytesMut::new();
            buf.put_varint(CLIENT_TCP_REQUEST_ID);
            buf.put_variable_slice(b"test.cc:80\xFF").unwrap();
            buf.put_padding(TCP_REQUEST_PADDING).unwrap();
            let mut stream = Cursor::new(buf.freeze());
            let request = read_tcp_request_message(&mut stream).await;
            assert!(matches!(request, Err(crate::Error::ParseError(e)) if e == "Invalid address"));
        }
    }

    mod send_tcp_response_message_tests {
        use std::io::Cursor;

        use bytes::Buf;
        use tokio::io::AsyncReadExt;

        use crate::{
            server::connection::send_tcp_response_message, utils::AsyncReadStreamExt, TcpResponse,
            SERVER_TCP_RESPONSE_STATUS_OK,
        };

        #[tokio::test]
        async fn test_send_tcp_response_message() {
            let mut buf = vec![0u8; 2048];
            let response = TcpResponse {
                status: SERVER_TCP_RESPONSE_STATUS_OK,
                message: "Hello".into(),
            };
            let mut stream = Cursor::new(&mut buf[..]);
            send_tcp_response_message(&mut stream, response)
                .await
                .unwrap();
            let mut stream = Cursor::new(buf);
            let status = stream.read_u8().await.unwrap();
            assert_eq!(status, SERVER_TCP_RESPONSE_STATUS_OK);
            let message_len = stream.read_varint().await.unwrap();
            let mut message_buf = vec![0u8; message_len as usize];
            stream.read_exact(&mut message_buf).await.unwrap();
            let message = String::from_utf8(message_buf).unwrap();
            assert_eq!(message, "Hello");
            stream.read_padding().await.unwrap();
            while stream.has_remaining() {
                assert_eq!(stream.read_u8().await.unwrap(), 0);
            }
        }
    }
}
