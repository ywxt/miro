mod auth;
mod config;
mod connection;
mod info;

pub use auth::*;
pub use config::*;
pub use connection::*;
pub use info::*;

use std::net::SocketAddr;

use crate::Error;

#[derive(Debug)]
pub struct Server {
    endpoint: s2n_quic::Server,
}

impl Server {
    pub fn new(endpoint: s2n_quic::Server) -> Self {
        Self { endpoint }
    }
}

impl Server {
    pub async fn accept_connection(&mut self) -> Result<Option<Connection>, Error> {
        let incoming = self.endpoint.accept().await;
        if let Some(conn) = incoming {
            Ok(Some(Connection::new(conn)))
        } else {
            Ok(None)
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        Ok(self.endpoint.local_addr()?)
    }
}
