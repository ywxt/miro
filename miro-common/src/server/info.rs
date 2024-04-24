use s2n_quic::provider::event::Subscriber;
use s2n_quic_core::transport::parameters::MaxDatagramFrameSize;

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub max_datagram_size: u64,
}

pub struct ConnectionInfoSubscriber;

impl Subscriber for ConnectionInfoSubscriber {
    type ConnectionContext = ConnectionInfo;

    fn create_connection_context(
        &mut self,
        _meta: &s2n_quic_core::event::api::ConnectionMeta,
        _info: &s2n_quic_core::event::api::ConnectionInfo,
    ) -> Self::ConnectionContext {
        ConnectionInfo {
            max_datagram_size: MaxDatagramFrameSize::RECOMMENDED,
        }
    }

    fn on_transport_parameters_received(
        &mut self,
        context: &mut Self::ConnectionContext,
        _meta: &s2n_quic_core::event::api::ConnectionMeta,
        event: &s2n_quic_core::event::api::TransportParametersReceived,
    ) {
        context.max_datagram_size = event.transport_parameters.max_datagram_frame_size;
    }
}
