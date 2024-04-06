use std::io;

use bytes::{Buf, BufMut};
use quinn::VarInt;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{CommonError, Padding, ProxyAddress};

pub(crate) trait AsyncReadStreamExt: AsyncRead {
    async fn read_varint(&mut self) -> Result<u64, CommonError>;
    async fn read_proxy_address(&mut self) -> Result<ProxyAddress, CommonError>;
    async fn read_padding(&mut self) -> Result<(), CommonError>;
}

impl<S> AsyncReadStreamExt for S
where
    S: AsyncRead + Unpin,
{
    async fn read_varint(&mut self) -> Result<u64, CommonError> {
        let mut result = 0;
        let mut shift = 0;
        loop {
            let mut buf = [0u8; 1];
            self.read_exact(&mut buf).await?;
            let byte = buf[0];
            result |= ((byte & 0x7F) as u64) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        Ok(result)
    }
    async fn read_proxy_address(&mut self) -> Result<ProxyAddress, CommonError> {
        let address_len = self.read_varint().await? as usize;
        if address_len == 0 {
            return Err(CommonError::ParseError("Invalid address length".into()));
        }
        let mut buf = vec![0u8; address_len];
        self.read_exact(&mut buf).await?;
        let address: ProxyAddress = String::from_utf8(buf)
            .map_err(|_| CommonError::ParseError("Invalid address".into()))?
            .parse()
            .map_err(|_| CommonError::ParseError("Invalid address".into()))?;
        Ok(address)
    }

    async fn read_padding(&mut self) -> Result<(), CommonError> {
        let padding_len = self.read_varint().await? as usize;
        let mut buf = vec![0u8; padding_len];
        self.read_exact(&mut buf).await?;
        Ok(())
    }
}

pub(crate) trait BufMutExt: BufMut {
    fn put_varint(&mut self, value: VarInt);
    fn put_proxy_address(&mut self, address: &ProxyAddress) -> Result<(), CommonError>;
    fn put_variable_slice(&mut self, slice: &[u8]) -> Result<(), CommonError>;
    fn put_padding(&mut self, padding: Padding) -> Result<(), CommonError>;
}

impl<B: BufMut> BufMutExt for B {
    fn put_varint(&mut self, value: VarInt) {
        let mut value = value.into_inner();
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
    fn put_proxy_address(&mut self, address: &ProxyAddress) -> Result<(), CommonError> {
        let address = address.to_string();
        self.put_varint(VarInt::from_u64(address.len() as u64).map_err(|_| {
            CommonError::VarIntBoundsExceeded("Address length exceeds bounds".into())
        })?);
        self.put_slice(address.as_bytes());
        Ok(())
    }

    fn put_variable_slice(&mut self, slice: &[u8]) -> Result<(), CommonError> {
        self.put_varint(VarInt::from_u64(slice.len() as u64).map_err(|_| {
            CommonError::VarIntBoundsExceeded("The slice length exceeds bounds".into())
        })?);
        self.put_slice(slice);
        Ok(())
    }

    fn put_padding(&mut self, padding: Padding) -> Result<(), CommonError> {
        let padding = padding.generate();
        self.put_variable_slice(padding.as_bytes())
    }
}

pub(crate) trait BufExt: Buf {
    fn read_u8(&mut self) -> Result<u8, CommonError>;
    fn read_u32(&mut self) -> Result<u32, CommonError>;
    fn read_u16(&mut self) -> Result<u16, CommonError>;
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), CommonError>;
    fn read_varint(&mut self) -> Result<u64, CommonError>;
    fn read_proxy_address(&mut self) -> Result<ProxyAddress, CommonError>;
    fn read_padding(&mut self) -> Result<(), CommonError>;
}

impl<B> BufExt for B
where
    B: Buf,
{
    fn read_varint(&mut self) -> Result<u64, CommonError> {
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

    fn read_proxy_address(&mut self) -> Result<ProxyAddress, CommonError> {
        let address_len = self.read_varint()? as usize;
        if address_len == 0 {
            return Err(CommonError::ParseError("Invalid address length".into()));
        }
        let mut buf = vec![0u8; address_len];
        self.read_exact(&mut buf)?;
        let address: ProxyAddress = String::from_utf8(buf)
            .map_err(|_| CommonError::ParseError("Invalid address".into()))?
            .parse()
            .map_err(|_| CommonError::ParseError("Invalid address".into()))?;
        Ok(address)
    }

    fn read_padding(&mut self) -> Result<(), CommonError> {
        let padding_len = self.read_varint()? as usize;
        self.advance(padding_len);
        Ok(())
    }

    fn read_u8(&mut self) -> Result<u8, CommonError> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), CommonError> {
        if self.remaining() < buf.len() {
            return Err(CommonError::IoError(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Unexpected EOF",
            )));
        }
        self.copy_to_slice(buf);
        Ok(())
    }

    fn read_u32(&mut self) -> Result<u32, CommonError> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    fn read_u16(&mut self) -> Result<u16, CommonError> {
        let mut buf = [0u8; 2];
        self.read_exact(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }
}
