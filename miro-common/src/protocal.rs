use bytes::Bytes;
use quinn::VarInt;
use std::{net::SocketAddr, num::ParseIntError, ops::Deref, str::FromStr, sync::Arc};

use crate::Error;

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

pub type DatagramSessionId = u32;
pub type DatagramPacketId = u16;

#[derive(Clone, Debug)]
pub struct DatagramFrame {
    pub session_id: u32,
    pub packet_id: u16,
    pub frame_id: u8,
    pub frame_count: u8,
    pub address: ProxyAddress,
    pub payload: Bytes,
}

#[derive(Clone, Debug)]
pub struct TcpRequest {
    pub address: ProxyAddress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyAddress(String);

impl ProxyAddress {
    pub fn new(s: String) -> Self {
        ProxyAddress(s)
    }

    pub async fn resolve(&self) -> Result<SocketAddr, Error> {
        tokio::net::lookup_host(self.0.as_str())
            .await
            .map_err(|e| Error::from(Arc::new(e)))?
            .next()
            .ok_or(Error::AddressResolutionError(self.0.clone().into()))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl From<String> for ProxyAddress {
    fn from(s: String) -> Self {
        ProxyAddress(s)
    }
}

impl From<&str> for ProxyAddress {
    fn from(s: &str) -> Self {
        ProxyAddress(s.to_string())
    }
}

impl ToString for ProxyAddress {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

impl AsRef<str> for ProxyAddress {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl Deref for ProxyAddress {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}
