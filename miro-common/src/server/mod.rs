mod auth;
mod config;
mod connection;

pub use auth::*;
pub use config::*;
pub use connection::*;

use std::{net::SocketAddr, sync::Arc};

use quinn::Endpoint;

use crate::Error;

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
    pub async fn accept_connection(&self) -> Result<Option<Connection>, Error> {
        let incoming = self.endpoint.accept().await;
        if let Some(conn) = incoming {
            let conn = conn.await?;
            Ok(Some(Connection::new(conn)))
        } else {
            Ok(None)
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.endpoint
            .local_addr()
            .map_err(|e| Error::IoError(Arc::new(e)))
    }
}
