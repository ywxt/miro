use std::time::Duration;

use crate::ServerMaxReceiveRate;

use super::Authentication;

#[derive(Clone, Debug)]
pub struct ConnectionConfig {
    pub cc_rx: ServerMaxReceiveRate,
    pub udp: bool,
    pub idle_timeout: Duration,
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
    idle_timeout: Duration,
    auth: Authentication,
}

impl ConnectionConfigBuilder {
    pub fn new(auth: Authentication) -> Self {
        Self {
            cc_rx: None,
            udp: false,
            idle_timeout: Duration::from_secs(60),
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

    pub fn idle_timeout(mut self, idle_timeout: Duration) -> Self {
        self.idle_timeout = idle_timeout;
        self
    }

    pub fn build(self) -> ConnectionConfig {
        ConnectionConfig {
            cc_rx: self.cc_rx.unwrap_or(ServerMaxReceiveRate::Auto),
            udp: self.udp,
            idle_timeout: self.idle_timeout,
            auth: self.auth,
        }
    }
}
