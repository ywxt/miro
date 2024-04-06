use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use bytes::{Bytes, BytesMut};
use moka::future::Cache;
use tokio::{
    net::{ToSocketAddrs, UdpSocket},
    sync::Mutex,
};

use crate::{DatagramPacketId, DatagramSessionId};

/// `(Session ID, Packet ID)`
pub type PacketCachedID = (DatagramSessionId, DatagramPacketId);

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

#[derive(Debug)]
pub struct DatagramSessionManager {
    recv_cache: Cache<DatagramSessionId, DatagramPacketCache>,
    socket_cache: Cache<DatagramSessionId, Arc<DatagramSocket>>,
    idle_timeout: Duration,
}

impl DatagramSessionManager {
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            recv_cache: Cache::builder().time_to_idle(idle_timeout).build(),
            socket_cache: Cache::builder().time_to_idle(idle_timeout).build(),
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

    pub async fn get_socket(
        &self,
        session_id: DatagramSessionId,
        bind_addr: SocketAddr,
    ) -> Result<Arc<DatagramSocket>, Arc<io::Error>> {
        self.socket_cache
            .try_get_with(session_id, async {
                DatagramSocket::bind(bind_addr).await.map(Arc::new)
            })
            .await
    }
}

#[derive(Debug)]
pub struct DatagramSocket {
    socket: UdpSocket,
}

impl DatagramSocket {
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        Ok(Self {
            socket: UdpSocket::bind(addr).await?,
        })
    }

    pub async fn send_to<A: ToSocketAddrs + Clone>(&self, buf: &[u8], addr: A) -> io::Result<()> {
        let mut send_len = 0;
        while send_len < buf.len() {
            let len = self.socket.send_to(&buf[send_len..], addr.clone()).await?;
            send_len += len;
        }
        Ok(())
    }
    pub async fn recv_from(&self) -> io::Result<(Bytes, SocketAddr)> {
        let mut buf = BytesMut::zeroed(65536);
        let (len, addr) = self.socket.recv_from(&mut buf[..]).await?;
        buf.truncate(len);
        Ok((buf.freeze(), addr))
    }
}
