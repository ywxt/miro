mod auth;
mod config;
mod connection;
mod info;
mod outbound;

pub use auth::*;
pub use config::*;
pub use connection::*;
pub use info::*;
pub use outbound::*;
use s2n_quic::provider::{datagram::default::Endpoint, tls};

use std::net::SocketAddr;

use crate::{datagram::QuicDatagramError, Error};

pub type DefaultServer =
    Server<PasswordAuthenticator, DefaultStreamProvider, DefaultDatagramProvider>;

#[derive(Debug)]
pub struct Server<Auth, OutboundStream, OutboundDatagram> {
    endpoint: s2n_quic::Server,
    config: ServerConfig<Auth, OutboundStream, OutboundDatagram>,
}

impl<
        Auth: Authenticator,
        OutboundStream: OutboundStreamProvider,
        OutboundDatagram: OutboundDatagramProvider,
    > Server<Auth, OutboundStream, OutboundDatagram>
{
    pub fn start(
        config: ServerConfig<Auth, OutboundStream, OutboundDatagram>,
    ) -> Result<Self, Error> {
        let mut tls_config = tls::default::Server::builder();
        for (cert, key) in config.certificates.iter() {
            tls_config = tls_config.with_certificate(cert, key)?;
        }
        let tls_config = tls_config.build()?;
        let datagram_provider = Endpoint::builder()
            .with_recv_capacity(200)
            .map_err(QuicDatagramError::from)?
            .build()
            .expect("Failed to build datagram provider");
        let server = s2n_quic::Server::builder()
            .with_tls(tls_config)
            .expect("unreachable")
            .with_io(config.local_addr)?
            .with_datagram(datagram_provider)
            .expect("unreachable")
            .start()?;
        Ok(Self {
            endpoint: server,
            config,
        })
    }

    pub async fn accept_connection(
        &mut self,
    ) -> Result<Option<Connection<Auth, OutboundStream, OutboundDatagram>>, Error> {
        let incoming = self.endpoint.accept().await;
        if let Some(conn) = incoming {
            let conn_config = ConnectionConfig::builder()
                .udp(self.config.udp_enabled)
                .max_receive_rate(self.config.bandwidth.clone())
                .udp_idle_timeout(self.config.udp_idle_timeout)
                .auth(self.config.auth.clone())
                .stream_outbound(self.config.stream_outbound.clone())
                .datagram_outbound(self.config.datagram_outbound.clone())
                .build();
            Ok(Some(Connection::new(conn, conn_config)))
        } else {
            Ok(None)
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        Ok(self.endpoint.local_addr()?)
    }
}
