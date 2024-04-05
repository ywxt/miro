mod auth;
mod config;
mod connection;
mod error;

pub use auth::*;
pub use config::*;
pub use connection::*;
pub use error::Error;

use quinn::Endpoint;

use crate::CommonError;

#[derive(Debug)]
pub struct Server {
    endpoint: Endpoint,
}

impl Server {
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }
}

impl Server {
    pub async fn accept_connection(&self) -> Result<Option<Connection>, CommonError> {
        let incoming = self.endpoint.accept().await;
        if let Some(conn) = incoming {
            let conn = conn.await?;
            Ok(Some(Connection::new(conn)))
        } else {
            Ok(None)
        }
    }
}
