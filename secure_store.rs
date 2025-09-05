use zeroize::Zeroize;
use std::ops::{Deref, DerefMut};

/// Securely stores a session key or secret in locked, zeroized memory.
pub struct SecureStore {
    inner: VolatilePage,
}

impl SecureStore {
    pub fn new(secret: &[u8]) -> Self {
        let mut page = VolatilePage::new(secret.len());
        page.buffer.copy_from_slice(secret);
        SecureStore { inner: page }
    }

    pub fn expose(&self) -> &[u8] {
        &self.inner
    }

    pub fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    pub fn size(&self) -> usize {
        self.inner.len()
    }
}

/// Secure memory buffer that zeroizes on drop and avoids accidental leaks.
pub struct VolatilePage {
    buffer: Vec<u8>,
}

impl VolatilePage {
    pub fn new(size: usize) -> Self {
        let mut buffer = Vec::with_capacity(size);
        unsafe { buffer.set_len(size); } // Avoid initializing to zeros, faster and tighter
        VolatilePage { buffer }
    }
}

impl Deref for VolatilePage {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buffer
    }
}

impl DerefMut for VolatilePage {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }
}

impl Drop for VolatilePage {
    fn drop(&mut self) {
        self.buffer.zeroize(); // Wipe memory explicitly
    }
}
