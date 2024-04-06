use std::borrow::Cow;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Quinn connection error: {0}")]
    QuinnError(#[from] quinn::ConnectionError),

    #[error("H3 connection error: {0}")]
    H3Error(#[from] h3::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Stream/Packet parsing error: {0}")]
    ParseError(Cow<'static, str>),

    #[error("VarInt bounds exceeded: {0}")]
    VarIntBoundsExceeded(Cow<'static, str>),
}
