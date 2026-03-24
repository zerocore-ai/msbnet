//! Intercept handler trait — hook point for the secrets layer.
//!
//! The TLS proxy calls this trait for each intercepted connection's plaintext
//! bytes between TLS termination and re-encryption. The default implementation
//! passes data through unchanged with zero allocation (borrows the input).
//! The secrets layer replaces it with substitution logic.

use std::{borrow::Cow, net::SocketAddr};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Called by the TLS proxy for each intercepted request's plaintext bytes.
///
/// Returns `Cow::Borrowed(data)` when the bytes are unchanged (zero-copy),
/// or `Cow::Owned(modified)` when substitution occurred. This avoids a
/// 16 KB allocation on every chunk for the common no-op and pass-through
/// cases.
pub trait InterceptHandler: Send + Sync {
    /// Inspect/modify outbound plaintext bytes before re-encryption.
    ///
    /// Returns the (possibly modified) bytes to send to the real server.
    fn on_request<'a>(&self, _dst: &SocketAddr, _sni: &str, data: &'a [u8]) -> Cow<'a, [u8]> {
        Cow::Borrowed(data)
    }

    /// Inspect/modify inbound plaintext bytes before re-encryption toward guest.
    ///
    /// Returns the (possibly modified) bytes to send to the guest.
    fn on_response<'a>(&self, _dst: &SocketAddr, _sni: &str, data: &'a [u8]) -> Cow<'a, [u8]> {
        Cow::Borrowed(data)
    }
}

/// No-op handler used when no secrets layer is active.
pub struct NoopHandler;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl InterceptHandler for NoopHandler {}
