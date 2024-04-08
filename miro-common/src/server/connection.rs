use std::{borrow::Cow, sync::Arc, time::Duration};

use axum::http::{Method, Request, Response, Version};
use bytes::{BufMut, Bytes};

use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc::Receiver,
};

use crate::{
    datagram::{
        DatagramPacket, DatagramSender, DatagramSessionManager, DatagramSocket,
        MAX_DATAGRAM_CHANNEL_CAPACITY,
    },
    utils::{AsyncReadStreamExt, BoxFuture, BufExt, BufMutExt},
    ClientHandshake, DatagramFrame, DatagramSessionId, ProxyAddress, ServerHandshake, TcpRequest,
    TcpResponse, AUTH_RESPONSE_PADDING, CLIENT_TCP_REQUEST_ID, HANDSHAKE_HEADER_AUTH,
    HANDSHAKE_HEADER_CC_RX, HANDSHAKE_HEADER_PADDING, HANDSHAKE_HEADER_UDP, HANDSHAKE_HOST,
    HANDSHAKE_PATH, HANDSHAKE_STATUS_OK, SERVER_TCP_RESPONSE_STATUS_OK, TCP_RESPONSE_PADDING,
};

use super::{Authentication, ConnectionConfig, ConnectionConfigBuilder, Error};

#[derive(Debug)]
pub struct Connection {
    conn: quinn::Connection,
    config: ConnectionConfig,
    session: DatagramSessionManager,
}

impl Connection {
    pub fn new(conn: quinn::Connection) -> Self {
        let config = ConnectionConfigBuilder::new(Authentication::new_password("Hello")).build();
        let idle_timeout = config.idle_timeout;
        Self {
            conn,
            config,
            session: DatagramSessionManager::new(idle_timeout),
        }
    }
}

impl Connection {
    #[tracing::instrument(level = "info", skip(self), fields(conn.ip = %self.conn.remote_address()))]
    pub async fn process(self) -> Result<(), Error> {
        let conn = self.conn.clone();
        tracing::info!("Processing connection");
        let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
            h3::server::Connection::new(h3_quinn::Connection::new(conn)).await?;
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
                if !self.config.authenticate(&client_handshake.auth).await? {
                    tracing::warn!(
                        "Authentication failed, serve the connection as a HTTP connection."
                    );
                    return serve_masquerading_http(request, stream, h3_conn).await;
                }
                tracing::debug!("Client authentication succeeded: {:?}", client_handshake);
                server_handshake(stream, &self.config).await?;
                tracing::info!(
                    "Handshake completed, serve the connection as a Hysteria connection."
                );
                drop(h3_conn);
                loop {
                    if let Some(result) = check_connection_closed(&self.conn) {
                        return result;
                    }
                    tokio::select! {
                        stream = self.conn.accept_bi() =>  {
                            let (send_stream, recv_stream) = stream?;

                            tokio::spawn(async move {
                                if let Err(e) =  process_tcp_request_message(recv_stream, send_stream).await {
                                    tracing::warn!("Error processing TCP request: {}", e);
                                }
                            });
                        }
                        datagram = self.conn.read_datagram() => {
                            if !self.config.udp || self.conn.max_datagram_size().is_none(){
                                tracing::info!("UDP is disabled, drop the packet");
                                continue;
                            }
                            let datagram = datagram?;
                            let cache = self.session.clone();
                            let conn = self.conn.clone();
                            let idle_timeout = self.config.idle_timeout;
                            tokio::spawn(async move {
                                if let Err(e) = process_udp_message(cache, conn ,datagram, idle_timeout).await {
                                    tracing::warn!("Error processing UDP message: {}", e);
                                }
                            });
                        }
                    }
                }
            }
            Ok(None) => {
                tracing::info!("No request received");
                Ok(())
            }
            Err(e) => {
                tracing::warn!("Error accepting request: {}", e);
                Err(Error::from(e))?
            }
        }
    }
}

fn check_connection_closed(conn: &quinn::Connection) -> Option<Result<(), Error>> {
    conn.close_reason().map(|reason| match reason {
        quinn::ConnectionError::ConnectionClosed(_)
        | quinn::ConnectionError::ApplicationClosed(_)
        | quinn::ConnectionError::LocallyClosed => {
            tracing::info!("Connection closed");
            Ok(())
        }
        quinn::ConnectionError::Reset => {
            tracing::info!("Connection reset");
            Ok(())
        }
        other => {
            tracing::warn!("Connection error: {:?}", other);
            Err(Error::from(other))
        }
    })
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
    mut connection: h3::server::Connection<h3_quinn::Connection, B>,
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
    config: &ConnectionConfig,
) -> Result<(), Error> {
    let response = ServerHandshake {
        udp: config.udp,
        cc_rx: config.cc_rx.clone(),
    };
    let response = build_server_handshake(response);
    stream.send_response(response).await?;
    stream.finish().await?;
    Ok(())
}

#[tracing::instrument(level = "debug", skip(recv_stream, send_stream))]
async fn process_tcp_request_message(
    mut recv_stream: impl AsyncRead + Unpin,
    mut send_stream: impl AsyncWrite + Unpin,
) -> Result<(), Error> {
    let request = read_tcp_request_message(&mut recv_stream).await?;
    tracing::debug!("Received TCP request: {:?}", request);
    let response = TcpResponse {
        status: SERVER_TCP_RESPONSE_STATUS_OK,
        message: "Miro".into(),
    };
    send_tcp_response_message(&mut send_stream, response).await?;
    let addr = request.address.resolve().await?;
    let outbound_stream = TcpStream::connect(addr)
        .await
        .map_err(|e| Error::IoError(Arc::new(e)))?;
    let (mut outbound_read, mut outbound_write) = outbound_stream.into_split();
    let result = tokio::join!(
        tokio::io::copy(&mut recv_stream, &mut outbound_write),
        tokio::io::copy(&mut outbound_read, &mut send_stream)
    );
    match result {
        (Ok(_), Ok(_)) => Ok(()),
        (Err(e), _) | (_, Err(e)) => Err(Error::IoError(Arc::new(e))),
    }
}

async fn read_tcp_request_message(
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<TcpRequest, Error> {
    let status = stream.read_varint().await?;
    if status != CLIENT_TCP_REQUEST_ID.into_inner() {
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

#[tracing::instrument(level = "debug", skip(cache, message))]
async fn process_udp_message(
    cache: DatagramSessionManager,
    conn: quinn::Connection,
    message: Bytes,
    idle_timeout: Duration,
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
    connection: quinn::Connection,
    mut receiver: Receiver<DatagramPacket>,
    session_id: DatagramSessionId,
    addr: &ProxyAddress,
    idle_timeout: Duration,
    invalidate_fn: impl FnOnce(DatagramSessionId) -> BoxFuture<()> + Send + 'static,
) -> Result<(), Error> {
    let addr = addr.resolve().await?;
    let local_addr = if addr.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    };
    let udp = DatagramSocket::bind(local_addr).await?;
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
        use axum::http::Method;
        use axum::http::Request;

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

        use quinn::VarInt;

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
            buf.put_varint(VarInt::from_u64(0).unwrap());
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
            buf.put_varint(VarInt::from_u64(0).unwrap());
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
