use std::{
    borrow::Cow,
    future::Future,
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
    time::Duration,
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use moka::future::Cache;
use s2n_quic::provider::datagram::default::Sender;

use tokio::sync::{mpsc, Mutex};

use crate::{
    server::ConnectionInfo,
    utils::{self, BoxFuture, BufMutExt},
    DatagramPacketId, DatagramSessionId, Error, ProxyAddress,
};

pub(crate) const MAX_DATAGRAM_CHANNEL_CAPACITY: usize = 32;
pub(crate) const MAX_DATAGRAM_SOCKET_CAPACITY: u64 = 128;

/// `(Session ID, Packet ID)`
pub type PacketCachedID = (DatagramSessionId, DatagramPacketId);

#[derive(Debug, Clone)]
pub struct DatagramPacket {
    pub session_id: DatagramSessionId,
    pub address: ProxyAddress,
    pub payload: Bytes,
}

impl DatagramPacket {
    /// This method is used to calculate the sent size of the packet
    ///
    /// The result contains the packet id and fragment description.
    pub fn sent_size(&self) -> u64 {
        self.header_size() + self.payload.len() as u64
    }

    /// This method is used to calculate the header size of the packet
    ///
    /// The result contains the packet id and fragment description.
    pub fn header_size(&self) -> u64 {
        // Session ID + Packet ID + Fragment ID + Fragment Count
        let mut len = 4 + 2 + 1 + 1;
        len += utils::varint_size(self.address.len() as u64);
        len += self.address.len() as u64;
        len
    }
}

#[derive(Debug, Clone)]
struct DatagramFrame<'a> {
    pub session_id: DatagramSessionId,
    pub packet_id: DatagramPacketId,
    pub frame_id: u8,
    pub frame_count: u8,
    pub address: &'a ProxyAddress,
    pub payload: Bytes,
}

impl DatagramFrame<'_> {
    /// This method is used to calculate the sent size of the packet
    pub fn sent_size(&self) -> u64 {
        // Session ID + Packet ID + Fragment ID + Fragment Count
        let mut len = 4 + 2 + 1 + 1;
        len += utils::varint_size(self.address.len() as u64);
        len += self.address.len() as u64;
        len += self.payload.len() as u64;
        len
    }
}

#[derive(Debug)]
pub struct DatagramFrameQueue {
    queue: Vec<Option<Bytes>>,
    remaining: usize,
    len: usize,
}

impl DatagramFrameQueue {
    pub fn new(size: usize) -> Self {
        Self {
            queue: vec![None; size],
            remaining: size,
            len: 0,
        }
    }
    pub fn is_full(&self) -> bool {
        self.remaining == 0
    }
    pub fn set(&mut self, index: usize, frame: Bytes) {
        let queue = &mut self.queue;
        if let Some(slot) = queue.get_mut(index) {
            match slot {
                Some(bytes) => {
                    self.len -= bytes.len();
                    *bytes = frame.clone();
                    self.len += frame.len();
                }
                None => {
                    *slot = Some(frame.clone());
                    self.remaining -= 1;
                    self.len += frame.len();
                }
            }
        }
    }
    pub fn to_bytes(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(self.len);
        for frame in self.queue.iter().flatten() {
            bytes.extend(frame)
        }
        bytes.freeze()
    }
}

#[derive(Debug, Clone)]
pub struct DatagramPacketCache {
    cache: Cache<PacketCachedID, Arc<Mutex<DatagramFrameQueue>>>,
}

impl DatagramPacketCache {
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            cache: Cache::builder().time_to_idle(idle_timeout).build(),
        }
    }
    pub async fn insert_and_try_collect(
        &self,
        key: PacketCachedID,
        frame_id: u8,
        frame: Bytes,
        frame_count: u8,
    ) -> Option<Bytes> {
        let queue = self
            .cache
            .get_with(key, async {
                Arc::new(Mutex::new(DatagramFrameQueue::new(frame_count as usize)))
            })
            .await;
        let mut queue = queue.lock().await;
        queue.set(frame_id as usize, frame);
        if queue.is_full() {
            let bytes = queue.to_bytes();
            self.cache.invalidate(&key).await;
            Some(bytes)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct DatagramSessionManager {
    recv_cache: Cache<DatagramSessionId, DatagramPacketCache>,
    socket_cache: Cache<DatagramSessionId, mpsc::Sender<DatagramPacket>>,
    idle_timeout: Duration,
}

impl DatagramSessionManager {
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            recv_cache: Cache::builder().time_to_idle(idle_timeout).build(),
            socket_cache: Cache::new(MAX_DATAGRAM_SOCKET_CAPACITY),
            idle_timeout,
        }
    }
    pub async fn insert_and_try_collect(
        &self,
        session_id: DatagramSessionId,
        packet_id: DatagramPacketId,
        frame_id: u8,
        payload: Bytes,
        frame_count: u8,
    ) -> Option<Bytes> {
        let key = (session_id, packet_id);
        let packet_cache = self
            .recv_cache
            .get_with(session_id, async {
                DatagramPacketCache::new(self.idle_timeout)
            })
            .await;
        packet_cache
            .insert_and_try_collect(key, frame_id, payload, frame_count)
            .await
    }

    pub async fn get_sender(
        &self,
        session_id: DatagramSessionId,
        init: impl Future<Output = Result<mpsc::Sender<DatagramPacket>, Error>>,
    ) -> Result<mpsc::Sender<DatagramPacket>, Arc<Error>> {
        self.socket_cache.try_get_with(session_id, init).await
    }

    pub(crate) fn get_session_invalidate_fn(
        &self,
    ) -> impl FnOnce(DatagramSessionId) -> BoxFuture<()> + Send + 'static {
        let socket_cache = self.socket_cache.clone();
        move |session_id| {
            Box::pin(async move {
                socket_cache.invalidate(&session_id).await;
            })
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum QuicDatagramError {
    #[error("Quic datagram fragmentation error: max_size: {max_size}, requested_size: {requested_size}, header_size: {header_size}")]
    QuicDatagramFragmentationError {
        max_size: u64,
        requested_size: u64,
        header_size: u64,
    },
    #[error("S2n Quic datagram error: {0}")]
    S2nQuicDatagramError(Cow<'static, str>),
    #[error("S2n Quic datagram build error: {0}")]
    S2nQuicDatagramBuildError(#[from] Arc<s2n_quic::provider::datagram::default::BuilderError>),
}

impl From<s2n_quic::provider::datagram::default::BuilderError> for QuicDatagramError {
    fn from(value: s2n_quic::provider::datagram::default::BuilderError) -> Self {
        Self::S2nQuicDatagramBuildError(Arc::new(value))
    }
}

#[derive(Debug)]
pub struct DatagramSender {
    conn: s2n_quic::connection::Handle,
    recorded_packet_id: AtomicU16,
}

impl DatagramSender {
    pub fn new(conn: s2n_quic::connection::Handle) -> Self {
        Self {
            conn,
            recorded_packet_id: AtomicU16::new(0),
        }
    }
    pub fn send(&self, packet: DatagramPacket) -> Result<(), Error> {
        let packet_id = self.recorded_packet_id.fetch_add(1, Ordering::SeqCst);
        let max_size = self
            .conn
            .query_event_context(|context: &ConnectionInfo| context.max_datagram_size)?;
        for frame in Self::fragment_packet(&packet, packet_id, max_size)? {
            self.send_frame(frame)?;
        }
        Ok(())
    }

    fn fragment_packet(
        packet: &DatagramPacket,
        packet_id: DatagramPacketId,
        max_size: u64,
    ) -> Result<impl Iterator<Item = DatagramFrame<'_>>, QuicDatagramError> {
        let packet_len = packet.sent_size();
        if packet_len <= max_size {
            Ok(DatagramFrameIter {
                session_id: packet.session_id,
                packet_id,
                frame_id: 0,
                frame_count: 1,
                address: &packet.address,
                payload: packet.payload.clone(),
                max_size: packet.payload.len() as u64,
            })
        } else {
            if max_size <= packet.header_size() {
                return Err(QuicDatagramError::QuicDatagramFragmentationError {
                    max_size,
                    requested_size: packet_len,
                    header_size: packet.header_size(),
                });
            }
            let max_payload_size = max_size - packet.header_size();
            let frame_count =
                (packet.payload.len() as u64 + max_payload_size - 1) / max_payload_size;
            if frame_count > u8::MAX as u64 {
                return Err(QuicDatagramError::QuicDatagramFragmentationError {
                    max_size,
                    requested_size: packet_len,
                    header_size: packet.header_size(),
                });
            }
            Ok(DatagramFrameIter {
                session_id: packet.session_id,
                packet_id,
                frame_id: 0,
                frame_count: frame_count as u8,
                address: &packet.address,
                payload: packet.payload.clone(),
                max_size: max_payload_size,
            })
        }
    }

    fn send_frame(&self, frame: DatagramFrame<'_>) -> Result<(), Error> {
        let mut buf = BytesMut::with_capacity(frame.sent_size() as usize);
        buf.put_u32(frame.session_id);
        buf.put_u16(frame.packet_id);
        buf.put_u8(frame.frame_id);
        buf.put_u8(frame.frame_count);
        buf.put_proxy_address(frame.address)?;
        buf.put(frame.payload);
        let data = buf.freeze();
        let result = self
            .conn
            .datagram_mut(|sender: &mut Sender| sender.send_datagram(data))?;

        match result {
            Ok(()) => Ok(()),
            Err(s2n_quic::provider::datagram::default::DatagramError::ConnectionError {
                error,
                ..
            }) => Err(error.into()),
            Err(e) => Err(QuicDatagramError::S2nQuicDatagramError(e.to_string().into()).into()),
        }
    }
}

#[derive(Debug)]
struct DatagramFrameIter<'a> {
    session_id: DatagramSessionId,
    packet_id: DatagramPacketId,
    frame_id: u8,
    frame_count: u8,
    address: &'a ProxyAddress,
    payload: Bytes,
    max_size: u64,
}

impl<'a> Iterator for DatagramFrameIter<'a> {
    type Item = DatagramFrame<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.frame_id >= self.frame_count {
            return None;
        }
        let frame = DatagramFrame {
            session_id: self.session_id,
            packet_id: self.packet_id,
            frame_id: self.frame_id,
            frame_count: self.frame_count,
            address: self.address,
            payload: if self.max_size > self.payload.remaining() as u64 {
                self.payload.split_off(0)
            } else {
                self.payload.split_to(self.max_size as usize)
            },
        };
        self.frame_id += 1;
        Some(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_datagram_no_fragment() {
        let session_id = 0x12345678;
        let packet_id = 0x1234;
        let address = ProxyAddress::new("12345678".to_string());
        let payload = Bytes::from_static(b"12345678".as_ref());
        let packet = DatagramPacket {
            session_id,
            address: address.clone(),
            payload: payload.clone(),
        };
        let max_size = 30;
        let frames: Vec<_> = DatagramSender::fragment_packet(&packet, packet_id, max_size)
            .unwrap()
            .collect();
        assert_eq!(frames.len(), 1);
        let frame = &frames[0];
        assert_eq!(frame.session_id, session_id);
        assert_eq!(frame.packet_id, packet_id);
        assert_eq!(frame.frame_id, 0);
        assert_eq!(frame.frame_count, 1);
        assert_eq!(frame.address, &address);
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn test_datagram_fragment() {
        let session_id = 0x12345678;
        let packet_id = 0x1234;
        let address = ProxyAddress::new("12345678".to_string());
        let payload = Bytes::from_static(b"12345678".as_ref());
        let packet = DatagramPacket {
            session_id,
            address: address.clone(),
            payload: payload.clone(),
        };
        let max_size = 24;
        let frames: Vec<_> = DatagramSender::fragment_packet(&packet, packet_id, max_size)
            .unwrap()
            .collect();
        assert_eq!(frames.len(), 2);
        let frame = &frames[0];
        assert_eq!(frame.session_id, session_id);
        assert_eq!(frame.packet_id, packet_id);
        assert_eq!(frame.frame_id, 0);
        assert_eq!(frame.frame_count, 2);
        assert_eq!(frame.address, &address);
        assert_eq!(&frame.payload[..], b"1234567");
        let frame = &frames[1];
        assert_eq!(frame.session_id, session_id);
        assert_eq!(frame.packet_id, packet_id);
        assert_eq!(frame.frame_id, 1);
        assert_eq!(frame.frame_count, 2);
        assert_eq!(frame.address, &address);
        assert_eq!(&frame.payload[..], b"8");
    }
}
