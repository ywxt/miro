use crate::ServerMaxReceiveRate;

use super::Authentication;

#[derive(Clone, Debug)]
pub struct ConnectionConfig {
    pub cc_rx: ServerMaxReceiveRate,
    pub udp: bool,
    auth: Authentication,
}

impl ConnectionConfig {
    pub async fn authenticate(&self, auth: &str) -> Result<bool, crate::CommonError> {
        self.auth.authenticate(auth).await
    }
}

pub struct ConnectionConfigBuilder {
    cc_rx: Option<ServerMaxReceiveRate>,
    udp: bool,
    auth: Authentication,
}

impl ConnectionConfigBuilder {
    pub fn new(auth: Authentication) -> Self {
        Self {
            cc_rx: None,
            udp: false,
            auth,
        }
    }

    pub fn max_receive_rate(mut self, max_receive_rate: ServerMaxReceiveRate) -> Self {
        self.cc_rx = Some(max_receive_rate);
        self
    }

    pub fn udp(mut self, udp: bool) -> Self {
        self.udp = udp;
        self
    }

    pub fn auth(mut self, auth: Authentication) -> Self {
        self.auth = auth;
        self
    }

    pub fn build(self) -> ConnectionConfig {
        ConnectionConfig {
            cc_rx: self.cc_rx.unwrap_or(ServerMaxReceiveRate::Auto),
            udp: self.udp,
            auth: self.auth,
        }
    }
}
