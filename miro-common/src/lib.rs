mod congestion;
mod error;
mod padding;
mod protocol;
mod utils;

pub mod client;
pub mod datagram;
pub mod server;

pub use error::Error;
pub use padding::*;
pub use protocol::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VarInt(u64);

impl VarInt {
    pub const fn from_u32(value: u32) -> Self {
        Self(value as u64)
    }

    pub const fn from_u16(value: u16) -> Self {
        Self(value as u64)
    }

    pub const fn from_u8(value: u8) -> Self {
        Self(value as u64)
    }

    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for VarInt {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value > 0x7FFF_FFFF_FFFF_FFFF {
            Err(())
        } else {
            Ok(Self(value))
        }
    }
}

impl TryFrom<usize> for VarInt {
    type Error = ();

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value > 0x7FFF_FFFF_FFFF_FFFF {
            Err(())
        } else {
            Ok(Self(value as u64))
        }
    }
}

impl From<u32> for VarInt {
    fn from(value: u32) -> Self {
        Self(value as u64)
    }
}

impl From<u16> for VarInt {
    fn from(value: u16) -> Self {
        Self(value as u64)
    }
}

impl From<u8> for VarInt {
    fn from(value: u8) -> Self {
        Self(value as u64)
    }
}

impl From<VarInt> for u64 {
    fn from(value: VarInt) -> Self {
        value.0
    }
}
