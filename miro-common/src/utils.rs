use std::{io, sync::Arc};

use crate::VarInt;
use bytes::{Buf, BufMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{Error, Padding, ProxyAddress};

pub type BoxFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + 'static + Send>>;

pub trait AsyncReadStreamExt: AsyncRead {
    async fn read_varint(&mut self) -> Result<u64, Error>;
    async fn read_proxy_address(&mut self) -> Result<ProxyAddress, Error>;
    async fn read_padding(&mut self) -> Result<(), Error>;
}

impl<S> AsyncReadStreamExt for S
where
    S: AsyncRead + Unpin,
{
    async fn read_varint(&mut self) -> Result<u64, Error> {
        let mut result = 0;
        let mut shift = 0;
        loop {
            let mut buf = [0u8; 1];
            self.read_exact(&mut buf)
                .await
                .map_err(|e| Error::IoError(Arc::new(e)))?;
            let byte = buf[0];
            result |= ((byte & 0x7F) as u64) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        Ok(result)
    }
    async fn read_proxy_address(&mut self) -> Result<ProxyAddress, Error> {
        let address_len = self.read_varint().await? as usize;
        if address_len == 0 {
            return Err(Error::ParseError("Invalid address length".into()));
        }
        let mut buf = vec![0u8; address_len];
        self.read_exact(&mut buf)
            .await
            .map_err(|e| Error::IoError(Arc::new(e)))?;
        let address: ProxyAddress = String::from_utf8(buf)
            .map_err(|_| Error::ParseError("Invalid address".into()))?
            .into();
        Ok(address)
    }

    async fn read_padding(&mut self) -> Result<(), Error> {
        let padding_len = self.read_varint().await? as usize;
        let mut buf = vec![0u8; padding_len];
        self.read_exact(&mut buf)
            .await
            .map_err(|e| Error::IoError(Arc::new(e)))?;
        Ok(())
    }
}

pub trait BufMutExt: BufMut {
    fn put_varint(&mut self, value: VarInt);
    fn put_proxy_address(&mut self, address: &ProxyAddress) -> Result<(), Error>;
    fn put_variable_slice(&mut self, slice: &[u8]) -> Result<(), Error>;
    fn put_padding(&mut self, padding: Padding) -> Result<(), Error>;
}

impl<B: BufMut> BufMutExt for B {
    fn put_varint(&mut self, value: VarInt) {
        let mut value = value.as_u64();
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            self.put_u8(byte);
            if value == 0 {
                break;
            }
        }
    }
    fn put_proxy_address(&mut self, address: &ProxyAddress) -> Result<(), Error> {
        let address = address.as_str();
        self.put_varint(
            VarInt::try_from(address.len())
                .map_err(|_| Error::VarIntBoundsExceeded("Address length exceeds bounds".into()))?,
        );
        self.put_slice(address.as_bytes());
        Ok(())
    }

    fn put_variable_slice(&mut self, slice: &[u8]) -> Result<(), Error> {
        self.put_varint(
            VarInt::try_from(slice.len() as u64).map_err(|_| {
                Error::VarIntBoundsExceeded("The slice length exceeds bounds".into())
            })?,
        );
        self.put_slice(slice);
        Ok(())
    }

    fn put_padding(&mut self, padding: Padding) -> Result<(), Error> {
        let padding = padding.generate();
        self.put_variable_slice(padding.as_bytes())
    }
}

pub trait BufExt: Buf {
    fn read_u8(&mut self) -> Result<u8, Error>;
    fn read_u32(&mut self) -> Result<u32, Error>;
    fn read_u16(&mut self) -> Result<u16, Error>;
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error>;
    fn read_varint(&mut self) -> Result<u64, Error>;
    fn read_proxy_address(&mut self) -> Result<ProxyAddress, Error>;
    fn read_padding(&mut self) -> Result<(), Error>;
}

impl<B> BufExt for B
where
    B: Buf,
{
    fn read_varint(&mut self) -> Result<u64, Error> {
        let mut result = 0;
        let mut shift = 0;
        loop {
            let byte = self.read_u8()?;
            result |= ((byte & 0x7F) as u64) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        Ok(result)
    }

    fn read_proxy_address(&mut self) -> Result<ProxyAddress, Error> {
        let address_len = self.read_varint()? as usize;
        if address_len == 0 {
            return Err(Error::ParseError("Invalid address length".into()));
        }
        let mut buf = vec![0u8; address_len];
        self.read_exact(&mut buf)?;
        let address: ProxyAddress = String::from_utf8(buf)
            .map_err(|_| Error::ParseError("Invalid address".into()))?
            .into();
        Ok(address)
    }

    fn read_padding(&mut self) -> Result<(), Error> {
        let padding_len = self.read_varint()? as usize;
        self.advance(padding_len);
        Ok(())
    }

    fn read_u8(&mut self) -> Result<u8, Error> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        if self.remaining() < buf.len() {
            return Err(Error::IoError(Arc::new(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Unexpected EOF",
            ))));
        }
        self.copy_to_slice(buf);
        Ok(())
    }

    fn read_u32(&mut self) -> Result<u32, Error> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    fn read_u16(&mut self) -> Result<u16, Error> {
        let mut buf = [0u8; 2];
        self.read_exact(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }
}

pub fn varint_size(value: u64) -> u64 {
    if value < 2u64.pow(6) {
        1
    } else if value < 2u64.pow(14) {
        2
    } else if value < 2u64.pow(30) {
        4
    } else if value < 2u64.pow(62) {
        8
    } else {
        unreachable!("malformed VarInt");
    }
}

/// Ignore the error if the connection is closed
pub fn transform_connection_error(
    err: s2n_quic_core::connection::Error,
) -> Option<s2n_quic_core::connection::Error> {
    match err {
        s2n_quic::connection::Error::Closed { .. } => None,
        s2n_quic::connection::Error::Transport { .. } => None,
        s2n_quic::connection::Error::Application { .. } => None,
        s2n_quic::connection::Error::ImmediateClose { .. } => None,
        _ => Some(err),
    }
}
