use std::{io, net::SocketAddr, sync::Arc};

use bytes::{Buf, Bytes, BytesMut};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream, ToSocketAddrs, UdpSocket,
    },
};

use crate::ProxyAddress;

#[async_trait::async_trait]
pub trait OutboundStreamProvider: Send + Sync + 'static {
    type StreamReader: AsyncRead + Unpin + Send + 'static;
    type StreamWriter: AsyncWrite + Unpin + Send + 'static;

    async fn direct(
        &self,
        proxy_address: &ProxyAddress,
    ) -> Result<(Self::StreamReader, Self::StreamWriter), io::Error>;
}

#[derive(Debug)]
pub struct DefaultStreamSocket {
    stream: TcpStream,
}

impl DefaultStreamSocket {
    async fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self, io::Error> {
        Ok(Self {
            stream: TcpStream::connect(addr).await?,
        })
    }

    fn split(self) -> (OwnedReadHalf, OwnedWriteHalf) {
        let (reader, writer) = self.stream.into_split();
        (reader, writer)
    }
}

#[derive(Debug, Clone)]
pub struct DefaultStreamProvider;

#[async_trait::async_trait]
impl OutboundStreamProvider for DefaultStreamProvider {
    type StreamReader = OwnedReadHalf;
    type StreamWriter = OwnedWriteHalf;
    async fn direct(
        &self,
        proxy_address: &ProxyAddress,
    ) -> Result<(Self::StreamReader, Self::StreamWriter), io::Error> {
        let stream = DefaultStreamSocket::connect(proxy_address.resolve().await?).await?;
        Ok(stream.split())
    }
}

#[async_trait::async_trait]
pub trait OutboundDatagramProvider: Send + Sync + 'static {
    type Socket: DatagramSocket + Send + Clone + 'static;
    async fn direct(
        &self,
        bind_address: impl ToSocketAddrs + Send,
    ) -> Result<Self::Socket, io::Error>;
}

#[derive(Debug, Clone)]
pub struct DefaultDatagramProvider;

#[async_trait::async_trait]
impl OutboundDatagramProvider for DefaultDatagramProvider {
    type Socket = DefaultDatagramSocket;

    async fn direct(
        &self,
        bind_address: impl ToSocketAddrs + Send,
    ) -> Result<Self::Socket, io::Error> {
        Ok(DefaultDatagramSocket::bind(bind_address).await?)
    }
}

#[async_trait::async_trait]
pub trait DatagramSocket {
    async fn send_to_proxy_address(
        &self,
        buf: Bytes,
        address: ProxyAddress,
    ) -> Result<(), io::Error>;
    async fn recv_from(&self) -> Result<(Bytes, SocketAddr), io::Error>;
}

#[derive(Debug, Clone)]
pub struct DefaultDatagramSocket {
    socket: Arc<UdpSocket>,
}

impl DefaultDatagramSocket {
    async fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self, io::Error> {
        Ok(Self {
            socket: Arc::new(UdpSocket::bind(addr).await?),
        })
    }

    async fn send_to(&self, mut buf: impl Buf, addr: SocketAddr) -> Result<(), io::Error> {
        while buf.has_remaining() {
            let len = self.socket.send_to(buf.chunk(), addr).await?;
            buf.advance(len);
        }
        Ok(())
    }

    async fn send_to_proxy_address(
        &self,
        buf: Bytes,
        address: ProxyAddress,
    ) -> Result<(), io::Error> {
        self.send_to(buf, address.resolve().await?).await
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddr), io::Error> {
        let mut buf = BytesMut::zeroed(65536);
        let (len, addr) = self.socket.recv_from(&mut buf[..]).await?;
        buf.truncate(len);
        Ok((buf.freeze(), addr))
    }
}

#[async_trait::async_trait]
impl DatagramSocket for DefaultDatagramSocket {
    async fn send_to_proxy_address(
        &self,
        buf: Bytes,
        address: ProxyAddress,
    ) -> Result<(), io::Error> {
        self.send_to_proxy_address(buf, address).await
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddr), io::Error> {
        self.recv_from().await
    }
}
