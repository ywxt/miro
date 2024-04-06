use bytes::BufMut;
use quinn::VarInt;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::CommonError;

pub(crate) trait AsyncReadStreamExt: AsyncRead {
    async fn read_varint(&mut self) -> Result<u64, CommonError>;
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
}

pub(crate) trait BufMutExt: BufMut {
    fn put_varint(&mut self, value: VarInt);
}

impl<T> BufMutExt for T
where
    T: bytes::BufMut,
{
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
}
