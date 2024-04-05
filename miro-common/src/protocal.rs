use quinn::VarInt;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    num::ParseIntError,
    str::FromStr,
};
use thiserror::Error;

pub const HANDSHAKE_PATH: &str = "/auth";
pub const HANDSHAKE_HOST: &str = "hysteria";
pub const HANDSHAKE_HEADER_AUTH: &str = "Hysteria-Auth";
pub const HANDSHAKE_HEADER_CC_RX: &str = "Hysteria-CC-RX";
pub const HANDSHAKE_HEADER_PADDING: &str = "Hysteria-Padding";
pub const HANDSHAKE_HEADER_UDP: &str = "Hysteria-UDP";

pub const HANDSHAKE_STATUS_OK: u16 = 233;

pub const CLIENT_TCP_REQUEST_ID: VarInt = VarInt::from_u32(0x401);
pub const SERVER_TCP_RESPONSE_STATUS_OK: u8 = 0x00;
pub const SERVER_TCP_RESPONSE_STATUS_ERROR: u8 = 0x01;

#[derive(Clone, Debug)]
pub enum ServerMaxReceiveRate {
    Auto,
    Specified(u32),
}

impl FromStr for ServerMaxReceiveRate {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "auto" {
            Ok(ServerMaxReceiveRate::Auto)
        } else {
            s.parse().map(ServerMaxReceiveRate::Specified)
        }
    }
}

impl ToString for ServerMaxReceiveRate {
    fn to_string(&self) -> String {
        match self {
            ServerMaxReceiveRate::Auto => "auto".to_string(),
            ServerMaxReceiveRate::Specified(v) => v.to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ClientHandshake {
    pub auth: String,
    pub cc_rx: u32,
}

#[derive(Clone, Debug)]
pub struct ServerHandshake {
    pub udp: bool,
    pub cc_rx: ServerMaxReceiveRate,
}

#[derive(Clone, Debug)]
pub struct TcpResponse {
    pub status: u8,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct TcpRequest {
    pub address: ProxyAddress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyAddress {
    pub host: ProxyHost,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyHost {
    Domain(String),
    IpV4(Ipv4Addr),
    IpV6(Ipv6Addr),
}

#[derive(Debug, Error)]
pub enum ParseAddressError {
    #[error("Invalid port, original address: {0}")]
    InvalidPort(String),
    #[error("Invalid host, original address: {0}")]
    InvalidHost(String),
    #[error("Invalid address, original address: {0}")]
    InvalidAddress(String),
}

impl ProxyAddress {
    pub fn new(host: ProxyHost, port: u16) -> Self {
        ProxyAddress { host, port }
    }
}

impl From<Ipv4Addr> for ProxyHost {
    fn from(ip: Ipv4Addr) -> Self {
        ProxyHost::IpV4(ip)
    }
}

impl From<Ipv6Addr> for ProxyHost {
    fn from(ip: Ipv6Addr) -> Self {
        ProxyHost::IpV6(ip)
    }
}

impl From<String> for ProxyHost {
    fn from(domain: String) -> Self {
        if let Ok(v4) = Ipv4Addr::from_str(&domain) {
            ProxyHost::IpV4(v4)
        } else if let Ok(v6) = Ipv6Addr::from_str(&domain) {
            ProxyHost::IpV6(v6)
        } else {
            ProxyHost::Domain(domain)
        }
    }
}

impl From<&str> for ProxyHost {
    fn from(domain: &str) -> Self {
        if let Ok(v4) = Ipv4Addr::from_str(domain) {
            ProxyHost::IpV4(v4)
        } else if let Ok(v6) = Ipv6Addr::from_str(domain) {
            ProxyHost::IpV6(v6)
        } else {
            ProxyHost::Domain(domain.to_string())
        }
    }
}

impl ToString for ProxyHost {
    fn to_string(&self) -> String {
        match self {
            ProxyHost::Domain(domain) => domain.clone(),
            ProxyHost::IpV4(ip) => ip.to_string(),
            ProxyHost::IpV6(ip) => ip.to_string(),
        }
    }
}

impl ToString for ProxyAddress {
    fn to_string(&self) -> String {
        format!("{}:{}", self.host.to_string(), self.port)
    }
}

impl FromStr for ProxyAddress {
    type Err = ParseAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(':');
        let host = parts
            .next()
            .ok_or_else(|| ParseAddressError::InvalidHost(s.to_string()))?;
        let port = parts
            .next()
            .ok_or_else(|| ParseAddressError::InvalidPort(s.to_string()))?;
        let port = port
            .parse::<u16>()
            .map_err(|_| ParseAddressError::InvalidPort(s.to_string()))?;
        if parts.next().is_some() {
            return Err(ParseAddressError::InvalidAddress(s.to_string()));
        }
        Ok(ProxyAddress::new(host.into(), port))
    }
}
