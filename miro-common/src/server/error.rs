use crate::CommonError;
use std::borrow::Cow;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Client handshake failed: {0}")]
    ClientHandshakeError(Cow<'static, str>),

    #[error("Client authentication failed")]
    ClientAuthError,

    #[error("Client TCP request message error: {0}")]
    TcpMessageError(String),

    #[error("{0}")]
    Other(#[from] CommonError),
}
