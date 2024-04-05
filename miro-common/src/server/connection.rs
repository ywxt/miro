use std::borrow::Cow;

use axum::http::{Method, Request, Response, Version};
use bytes::{Buf, BufMut, Bytes};
use quinn::VarInt;
use quinn_proto::coding::Codec;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    ClientHandshake, CommonError, ProxyAddress, ServerHandshake, TcpRequest, TcpResponse,
    AUTH_RESPONSE_PADDING, CLIENT_TCP_REQUEST_ID, HANDSHAKE_HEADER_AUTH, HANDSHAKE_HEADER_CC_RX,
    HANDSHAKE_HEADER_PADDING, HANDSHAKE_HEADER_UDP, HANDSHAKE_HOST, HANDSHAKE_PATH,
    HANDSHAKE_STATUS_OK, SERVER_TCP_RESPONSE_STATUS_OK, TCP_RESPONSE_PADDING,
};

use super::{Authentication, ConnectionConfig, ConnectionConfigBuilder, Error};

#[derive(Debug)]
pub struct Connection {
    conn: quinn::Connection,
    config: ConnectionConfig,
}

impl Connection {
    pub fn new(conn: quinn::Connection) -> Self {
        Self {
            conn,
            config: ConnectionConfigBuilder::new(Authentication::new_password("Hello")).build(),
        }
    }
}

impl Connection {
    #[tracing::instrument(level = "info", skip(self))]
    pub async fn process(&self) -> Result<(), Error> {
        let conn = self.conn.clone();
        tracing::info!("Processing connection: {}", conn.remote_address());
        let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
            h3::server::Connection::new(h3_quinn::Connection::new(conn))
                .await
                .map_err(CommonError::from)?;
        match h3_conn.accept().await {
            Ok(Some((request, stream))) => {
                tracing::info!("Stream ID: {:?}", stream.id());
                tracing::debug!("Received request: {:?}", request);

                let client_handshake = match client_handshake(request.clone()).await {
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
                tracing::debug!("Handshake completed, serve the connection as a TCP connection.");
                drop(h3_conn);
                loop {
                    let (send_stream, recv_stream) =
                        self.conn.accept_bi().await.map_err(CommonError::from)?;

                    process_tcp_request_message(recv_stream, send_stream).await?;
                }
            }
            Ok(None) => {
                tracing::info!("No request received");
                Ok(())
            }
            Err(e) => {
                tracing::warn!("Error accepting request: {}", e);
                Err(CommonError::from(e))?
            }
        }
    }
}

type ClientHandshakeError = Cow<'static, str>;

async fn client_handshake<T>(request: Request<T>) -> Result<ClientHandshake, ClientHandshakeError> {
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
    while let Some((request, stream)) = connection.accept().await.map_err(CommonError::from)? {
        tracing::debug!("Received request: {:?}", request);
        send_404(stream).await?;
    }
    connection.shutdown(0).await.map_err(CommonError::from)?;
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
    stream
        .send_response(response)
        .await
        .map_err(CommonError::from)?;
    stream.finish().await.map_err(CommonError::from)?;
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
    stream
        .send_response(response)
        .await
        .map_err(CommonError::from)?;
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
        message: "Hello, world!".into(),
    };
    send_tcp_response_message(&mut send_stream, response).await?;
    tracing::error!("TCP proxy not implemented yet");
    // TODO: Implement TCP proxy
    Ok(())
}

async fn read_tcp_request_message(
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<TcpRequest, Error> {
    let mut buf = bytes::BytesMut::zeroed(16);
    stream
        .read_exact(&mut buf)
        .await
        .map_err(CommonError::from)?;
    let mut buf = buf.freeze();
    let status = VarInt::decode(&mut buf).map_err(|e| Error::TcpMessageError(format!("{}", e)))?;
    if status != CLIENT_TCP_REQUEST_ID {
        return Err(Error::TcpMessageError(format!(
            "Invalid request ID: {}",
            status
        )));
    }
    let address_len =
        VarInt::decode(&mut buf).map_err(|e| Error::TcpMessageError(format!("{}", e)))?;
    if address_len <= VarInt::from_u32(0) {
        return Err(Error::TcpMessageError("Invalid address length".into()));
    }
    let mut address_buf = bytes::BytesMut::with_capacity(address_len.into_inner() as usize);
    let remaining_size = buf.remaining();
    address_buf.put(buf.chunk());
    address_buf.resize(address_buf.capacity(), 0);

    stream
        .read_exact(&mut address_buf[remaining_size..])
        .await
        .map_err(CommonError::from)?;
    let address_buf = address_buf.freeze();
    let address: ProxyAddress = String::from_utf8(address_buf.to_vec())
        .map_err(|_| Error::TcpMessageError("Invalid address".into()))?
        .parse()
        .map_err(|_| Error::TcpMessageError("Invalid address".into()))?;
    let mut padding_len_buf = bytes::BytesMut::zeroed(8);
    stream
        .read_buf(&mut padding_len_buf)
        .await
        .map_err(CommonError::from)?;
    let mut padding_len_buf = padding_len_buf.freeze();
    let padding_len = VarInt::decode(&mut padding_len_buf)
        .map_err(|e| Error::TcpMessageError(format!("{}", e)))?;
    if padding_len <= VarInt::from_u32(0) {
        return Err(Error::TcpMessageError("Invalid padding length".into()));
    }
    let mut padding_buf =
        bytes::BytesMut::zeroed(padding_len.into_inner() as usize - padding_len_buf.remaining());
    stream
        .read_exact(&mut padding_buf)
        .await
        .map_err(CommonError::from)?;
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
    let message_len = VarInt::from_u64(message.len() as u64)
        .map_err(|e| Error::TcpMessageError(format!("{}", e)))?;
    message_len.encode(&mut buf);
    buf.put(message);
    let padding = TCP_RESPONSE_PADDING.generate();
    let padding_bytes = padding.as_bytes();
    let padding_len = VarInt::from_u64(padding_bytes.len() as u64)
        .map_err(|e| Error::TcpMessageError(format!("{}", e)))?;
    padding_len.encode(&mut buf);
    buf.put(padding_bytes);
    stream.write_all(&buf).await.map_err(CommonError::from)?;
    Ok(())
}
