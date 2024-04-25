use std::{borrow::Cow, net::SocketAddr};

use async_trait::async_trait;

use crate::Error;

#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate(
        &self,
        auth: &str,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> Result<bool, Error>;
}

#[derive(Debug, Clone)]
pub struct PasswordAuthenticator {
    password: Cow<'static, str>,
}

impl PasswordAuthenticator {
    pub fn new(password: impl Into<Cow<'static, str>>) -> Self {
        Self {
            password: password.into(),
        }
    }
}

#[async_trait]
impl Authenticator for PasswordAuthenticator {
    async fn authenticate(&self, auth: &str, _: SocketAddr, _: SocketAddr) -> Result<bool, Error> {
        Ok(self.password == auth)
    }
}
