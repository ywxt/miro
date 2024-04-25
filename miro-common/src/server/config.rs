use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use crate::ServerMaxReceiveRate;

use super::{Authenticator, OutboundDatagramProvider, OutboundStreamProvider};

#[derive(Debug)]
pub struct ConnectionConfig<Auth, OutboundStream, OutboundDatagram> {
    pub(crate) cc_rx: ServerMaxReceiveRate,
    pub(crate) udp: bool,
    pub(crate) udp_idle_timeout: Duration,
    pub(crate) auth: Arc<Auth>,
    pub(crate) stream_outbound: Arc<OutboundStream>,
    pub(crate) datagram_outbound: Arc<OutboundDatagram>,
}

impl ConnectionConfig<(), (), ()> {
    pub fn builder() -> ConnectionConfigBuilder<(), (), ()> {
        ConnectionConfigBuilder {
            cc_rx: ServerMaxReceiveRate::Auto,
            udp: false,
            udp_idle_timeout: Duration::from_secs(5000),
            auth: Arc::new(()),
            stream_outbound: Arc::new(()),
            datagram_outbound: Arc::new(()),
        }
    }
}

pub struct ConnectionConfigBuilder<Auth, OutboundStream, OutboundDatagram> {
    cc_rx: ServerMaxReceiveRate,
    udp: bool,
    udp_idle_timeout: Duration,
    auth: Arc<Auth>,
    stream_outbound: Arc<OutboundStream>,
    datagram_outbound: Arc<OutboundDatagram>,
}

impl<Auth, OutboundStream, OutboundDatagram>
    ConnectionConfigBuilder<Auth, OutboundStream, OutboundDatagram>
{
    pub fn max_receive_rate(mut self, max_receive_rate: impl Into<ServerMaxReceiveRate>) -> Self {
        self.cc_rx = max_receive_rate.into();
        self
    }

    pub fn udp(mut self, udp: bool) -> Self {
        self.udp = udp;
        self
    }

    pub fn udp_idle_timeout(mut self, udp_idle_timeout: Duration) -> Self {
        self.udp_idle_timeout = udp_idle_timeout;
        self
    }

    pub fn auth<Authentication: Authenticator>(
        self,
        auth: impl Into<Arc<Authentication>>,
    ) -> ConnectionConfigBuilder<Authentication, OutboundStream, OutboundDatagram> {
        ConnectionConfigBuilder {
            cc_rx: self.cc_rx,
            udp: self.udp,
            udp_idle_timeout: self.udp_idle_timeout,
            auth: auth.into(),
            stream_outbound: self.stream_outbound,
            datagram_outbound: self.datagram_outbound,
        }
    }

    pub fn stream_outbound<OutStream: OutboundStreamProvider>(
        self,
        stream_outbound: impl Into<Arc<OutStream>>,
    ) -> ConnectionConfigBuilder<Auth, OutStream, OutboundDatagram> {
        ConnectionConfigBuilder {
            cc_rx: self.cc_rx,
            udp: self.udp,
            udp_idle_timeout: self.udp_idle_timeout,
            auth: self.auth,
            stream_outbound: stream_outbound.into(),
            datagram_outbound: self.datagram_outbound,
        }
    }

    pub fn datagram_outbound<OutDatagram: OutboundDatagramProvider>(
        self,
        datagram_outbound: impl Into<Arc<OutDatagram>>,
    ) -> ConnectionConfigBuilder<Auth, OutboundStream, OutDatagram> {
        ConnectionConfigBuilder {
            cc_rx: self.cc_rx,
            udp: self.udp,
            udp_idle_timeout: self.udp_idle_timeout,
            auth: self.auth,
            stream_outbound: self.stream_outbound,
            datagram_outbound: datagram_outbound.into(),
        }
    }
}

impl<
        Auth: Authenticator,
        OutboundStream: OutboundStreamProvider,
        OutboundDatagram: OutboundDatagramProvider,
    > ConnectionConfigBuilder<Auth, OutboundStream, OutboundDatagram>
{
    pub fn build(self) -> ConnectionConfig<Auth, OutboundStream, OutboundDatagram> {
        ConnectionConfig {
            cc_rx: self.cc_rx,
            udp: self.udp,
            udp_idle_timeout: self.udp_idle_timeout,
            auth: self.auth,
            stream_outbound: self.stream_outbound,
            datagram_outbound: self.datagram_outbound,
        }
    }
}

#[derive(Debug)]
pub struct ServerConfig<Auth, OutboundStream, OutboundDatagram> {
    pub(crate) local_addr: std::net::SocketAddr,
    /// `certificates` is a list of `(certificate, private_key)` pairs.
    pub(crate) certificates: Vec<(String, String)>,
    pub(crate) bandwidth: ServerMaxReceiveRate,
    pub(crate) udp_enabled: bool,
    pub(crate) udp_idle_timeout: Duration,
    pub(crate) auth: Arc<Auth>,
    pub(crate) stream_outbound: Arc<OutboundStream>,
    pub(crate) datagram_outbound: Arc<OutboundDatagram>,
}

impl ServerConfig<(), (), ()> {
    pub fn builder() -> ServerConfigBuilder<(), (), ()> {
        ServerConfigBuilder {
            local_addr: SocketAddr::new(
                IpAddr::from_str("::0").expect("Failed to parse IP address"),
                0,
            ),
            certificates: Vec::new(),
            bandwidth: ServerMaxReceiveRate::Auto,
            udp_enabled: false,
            udp_idle_timeout: Duration::from_secs(5000),
            auth: Arc::new(()),
            stream_outbound: Arc::new(()),
            datagram_outbound: Arc::new(()),
        }
    }
}

#[derive(Debug)]
pub struct ServerConfigBuilder<Auth, OutboundStream, OutboundDatagram> {
    local_addr: std::net::SocketAddr,
    certificates: Vec<(String, String)>,
    bandwidth: ServerMaxReceiveRate,
    udp_enabled: bool,
    udp_idle_timeout: Duration,
    auth: Arc<Auth>,
    stream_outbound: Arc<OutboundStream>,
    datagram_outbound: Arc<OutboundDatagram>,
}

impl<Auth, OutboundStream, OutboundDatagram>
    ServerConfigBuilder<Auth, OutboundStream, OutboundDatagram>
{
    pub fn local_addr(mut self, local_addr: std::net::SocketAddr) -> Self {
        self.local_addr = local_addr;
        self
    }

    pub fn certificates(mut self, certificates: Vec<(String, String)>) -> Self {
        self.certificates = certificates;
        self
    }

    pub fn add_certificate(mut self, cert: String, key: String) -> Self {
        self.certificates.push((cert, key));
        self
    }

    pub fn bandwidth(mut self, bandwidth: impl Into<ServerMaxReceiveRate>) -> Self {
        self.bandwidth = bandwidth.into();
        self
    }

    pub fn udp_enabled(mut self, udp_enabled: bool) -> Self {
        self.udp_enabled = udp_enabled;
        self
    }

    pub fn udp_idle_timeout(mut self, udp_idle_timeout: Duration) -> Self {
        self.udp_idle_timeout = udp_idle_timeout;
        self
    }

    pub fn auth<Authentication: Authenticator>(
        self,
        auth: impl Into<Arc<Authentication>>,
    ) -> ServerConfigBuilder<Authentication, OutboundStream, OutboundDatagram> {
        ServerConfigBuilder {
            local_addr: self.local_addr,
            certificates: self.certificates,
            bandwidth: self.bandwidth,
            udp_enabled: self.udp_enabled,
            udp_idle_timeout: self.udp_idle_timeout,
            auth: auth.into(),
            stream_outbound: self.stream_outbound,
            datagram_outbound: self.datagram_outbound,
        }
    }

    pub fn stream_outbound<OutStream: OutboundStreamProvider>(
        self,
        stream_outbound: impl Into<Arc<OutStream>>,
    ) -> ServerConfigBuilder<Auth, OutStream, OutboundDatagram> {
        ServerConfigBuilder {
            local_addr: self.local_addr,
            certificates: self.certificates,
            bandwidth: self.bandwidth,
            udp_enabled: self.udp_enabled,
            udp_idle_timeout: self.udp_idle_timeout,
            auth: self.auth,
            stream_outbound: stream_outbound.into(),
            datagram_outbound: self.datagram_outbound,
        }
    }

    pub fn datagram_outbound<OutDatagram: OutboundDatagramProvider>(
        self,
        datagram_outbound: impl Into<Arc<OutDatagram>>,
    ) -> ServerConfigBuilder<Auth, OutboundStream, OutDatagram> {
        ServerConfigBuilder {
            local_addr: self.local_addr,
            certificates: self.certificates,
            bandwidth: self.bandwidth,
            udp_enabled: self.udp_enabled,
            udp_idle_timeout: self.udp_idle_timeout,
            auth: self.auth,
            stream_outbound: self.stream_outbound,
            datagram_outbound: datagram_outbound.into(),
        }
    }
}

impl<
        Auth: Authenticator,
        OutboundStream: OutboundStreamProvider,
        OutboundDatagram: OutboundDatagramProvider,
    > ServerConfigBuilder<Auth, OutboundStream, OutboundDatagram>
{
    pub fn build(self) -> ServerConfig<Auth, OutboundStream, OutboundDatagram> {
        ServerConfig {
            local_addr: self.local_addr,
            certificates: self.certificates,
            bandwidth: self.bandwidth,
            udp_enabled: self.udp_enabled,
            udp_idle_timeout: self.udp_idle_timeout,
            auth: self.auth,
            stream_outbound: self.stream_outbound,
            datagram_outbound: self.datagram_outbound,
        }
    }
}
