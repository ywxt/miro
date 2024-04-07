use std::{future::Future, net::SocketAddr, sync::{atomic::{AtomicU16, Ordering}, Arc}, time::Duration};

use bytes::{Buf, Bytes, BytesMut};
use moka::future::Cache;
use tokio::{
    net::{ToSocketAddrs, UdpSocket},
    sync::{mpsc, Mutex},
};

use crate::{utils::BoxFuture, CommonError, DatagramPacketId, DatagramSessionId, ProxyAddress};

pub(crate) const MAX_DATAGRAM_CHANNEL_CAPACITY: usize = 32;
pub(crate) const MAX_DATAGRAM_SOCKET_CAPACITY: u64 = 128;

/// `(Session ID, Packet ID)`
pub type PacketCachedID = (DatagramSessionId, DatagramPacketId);

#[derive(Debug)]
pub struct DatagramPacket {
    pub session_id: DatagramSessionId,
    pub address: ProxyAddress,
    pub payload: Bytes,
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
        init: impl Future<Output = Result<mpsc::Sender<DatagramPacket>, CommonError>>,
    ) -> Result<mpsc::Sender<DatagramPacket>, Arc<CommonError>> {
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

#[derive(Debug, Clone)]
pub struct DatagramSocket {
    socket: Arc<UdpSocket>,
}

impl DatagramSocket {
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self, CommonError> {
        Ok(Self {
            socket: Arc::new(
                UdpSocket::bind(addr)
                    .await
                    .map_err(|e| CommonError::IoError(Arc::new(e)))?,
            ),
        })
    }

    pub async fn send_to(&self, mut buf: impl Buf, addr: SocketAddr) -> Result<(), CommonError> {
        while buf.has_remaining() {
            let len = self
                .socket
                .send_to(buf.chunk(), addr)
                .await
                .map_err(|e| CommonError::IoError(Arc::new(e)))?;
            buf.advance(len);
        }
        Ok(())
    }

    pub async fn send_to_proxy_address(
        &self,
        buf: Bytes,
        address: ProxyAddress,
    ) -> Result<(), CommonError> {
        self.send_to(buf, address.resolve().await?).await
    }

    pub async fn recv_from(&self) -> Result<(Bytes, SocketAddr), CommonError> {
        let mut buf = BytesMut::zeroed(65536);
        let (len, addr) = self
            .socket
            .recv_from(&mut buf[..])
            .await
            .map_err(|e| CommonError::IoError(Arc::new(e)))?;
        buf.truncate(len);
        Ok((buf.freeze(), addr))
    }
}

#[derive(Debug)]
pub struct DatagramSender {
    _conn: quinn::Connection,
    recorded_packet_id: AtomicU16,
}

impl DatagramSender {
    pub fn new(conn: quinn::Connection) -> Self {
        Self { _conn: conn, recorded_packet_id: AtomicU16::new(0) }
    }
    pub async fn send(&self, _packet: DatagramPacket) -> Result<(), CommonError> {
        let _packet_id = self.recorded_packet_id.fetch_add(1, Ordering::SeqCst);
        unimplemented!("QuicDatagramSender::send")
    }
}
