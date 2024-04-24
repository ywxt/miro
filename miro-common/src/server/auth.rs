use std::borrow::Cow;

use async_trait::async_trait;

use crate::Error;

#[async_trait]
trait Authenticator {
    async fn authenticate(&self, auth: &str) -> Result<bool, Error>;
}

#[derive(Debug, Clone)]
pub enum Authentication {
    Password(PasswordAuthenticator),
}

impl Authentication {
    pub fn new_password(password: impl Into<Cow<'static, str>>) -> Self {
        Self::Password(PasswordAuthenticator::new(password))
    }
}

impl Authentication {
    pub async fn authenticate(&self, auth: &str) -> Result<bool, Error> {
        match self {
            Self::Password(authenticator) => authenticator.authenticate(auth).await,
        }
    }
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
    async fn authenticate(&self, auth: &str) -> Result<bool, Error> {
        Ok(self.password == auth)
    }
}
