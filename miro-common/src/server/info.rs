use s2n_quic::provider::event::Subscriber;

const MAX_DATAGRAM_FRAME_SIZE: u64 = 65535;

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub max_datagram_size: u64,
}

pub struct ConnectionInfoSubscriber;

impl Subscriber for ConnectionInfoSubscriber {
    type ConnectionContext = ConnectionInfo;

    fn create_connection_context(
        &mut self,
        _meta: &s2n_quic::provider::event::ConnectionMeta,
        _info: &s2n_quic::provider::event::ConnectionInfo,
    ) -> Self::ConnectionContext {
        ConnectionInfo {
            max_datagram_size: MAX_DATAGRAM_FRAME_SIZE,
        }
    }

    fn on_transport_parameters_received(
        &mut self,
        context: &mut Self::ConnectionContext,
        _meta: &s2n_quic::provider::event::ConnectionMeta,
        event: &s2n_quic::provider::event::events::TransportParametersReceived,
    ) {
        context.max_datagram_size = event.transport_parameters.max_datagram_frame_size;
    }
}
