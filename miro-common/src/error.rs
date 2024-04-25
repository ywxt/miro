use std::{borrow::Cow, sync::Arc};

use thiserror::Error;

use crate::datagram::QuicDatagramError;

#[derive(Debug, Error, Clone)]
pub enum Error {
    #[error("Quic connection error: {0}")]
    QuicConnectionError(#[from] s2n_quic::connection::Error),

    #[error("H3 connection error: {0}")]
    H3Error(#[from] s2n_quic_h3::h3::Error),

    #[error("S2n Quic query error: {0}")]
    S2nQuicQueryError(#[from] s2n_quic::provider::event::query::Error),

    #[error("S2n TLS error: {0}")]
    TlsError(#[from] Arc<s2n_quic::provider::tls::default::error::Error>),

    #[error("S2n endpoint start error: {0}")]
    StartError(#[from] Arc<s2n_quic::provider::StartError>),

    #[error("IO error: {0}")]
    IoError(#[from] Arc<std::io::Error>),

    #[error("Datagram error: {0}")]
    QuicDatagramError(#[from] QuicDatagramError),

    #[error("Stream/Packet parsing error: {0}")]
    ParseError(Cow<'static, str>),

    #[error("VarInt bounds exceeded: {0}")]
    VarIntBoundsExceeded(Cow<'static, str>),

    #[error("Address resolution error: {0}")]
    AddressResolutionError(Cow<'static, str>),

    #[error("Hysteria handshake failed: {0}")]
    HysteriaHandshakeError(Cow<'static, str>),

    #[error("Hysteria authentication failed: {0}")]
    HysteriaAuthError(Arc<dyn std::error::Error + Send + Sync>),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(Arc::new(e))
    }
}

impl From<s2n_quic::provider::tls::default::error::Error> for Error {
    fn from(value: s2n_quic::provider::tls::default::error::Error) -> Self {
        Self::TlsError(Arc::new(value))
    }
}

impl From<s2n_quic::provider::StartError> for Error {
    fn from(value: s2n_quic::provider::StartError) -> Self {
        Self::StartError(Arc::new(value))
    }
}
