use std::{borrow::Cow, sync::Arc};

use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum Error {
    #[error("Quinn connection error: {0}")]
    QuinnConnectionError(#[from] quinn::ConnectionError),

    #[error("H3 connection error: {0}")]
    H3Error(#[from] h3::Error),

    #[error("IO error: {0}")]
    IoError(#[from] Arc<std::io::Error>),

    #[error("Quinn datagram error: {0}")]
    DatagramError(#[from] quinn::SendDatagramError),

    #[error("Stream/Packet parsing error: {0}")]
    ParseError(Cow<'static, str>),

    #[error("VarInt bounds exceeded: {0}")]
    VarIntBoundsExceeded(Cow<'static, str>),

    #[error("Address resolution error: {0}")]
    AddressResolutionError(Cow<'static, str>),

    #[error("Hysteria handshake failed: {0}")]
    HysteriaHandshakeError(Cow<'static, str>),

    #[error("Hysteria authentication failed")]
    HysteriaAuthError,
}
