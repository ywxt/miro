use rand::Rng;

const PADDING_CHARS: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

pub const AUTH_REQEUST_PADDING: Padding = Padding {
    min: 256,
    max: 2048,
};
pub const AUTH_RESPONSE_PADDING: Padding = Padding {
    min: 256,
    max: 2048,
};
pub const TCP_REQUEST_PADDING: Padding = Padding { min: 64, max: 512 };
pub const TCP_RESPONSE_PADDING: Padding = Padding {
    min: 128,
    max: 1024,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Padding {
    min: usize,
    max: usize,
}

impl Padding {
    pub fn generate(&self) -> String {
        let len = rand::thread_rng().gen_range(self.min..self.max);
        let mut padding = Vec::with_capacity(len);
        for _ in 0..len {
            padding.push(PADDING_CHARS[rand::thread_rng().gen_range(0..PADDING_CHARS.len())]);
        }
        unsafe { String::from_utf8_unchecked(padding) }
    }
}
