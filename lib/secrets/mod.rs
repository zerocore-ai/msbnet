//! Secret placeholder substitution for sandbox egress traffic.
//!
//! Secrets use **placeholder-based protection**: the sandbox receives a
//! placeholder string (e.g., `$MSB_a8f3b2c1`) instead of the real secret value.
//! The TLS proxy's intercept handler substitutes the real value only when
//! outbound requests go to allowed hosts.

mod config;
mod handler;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use config::*;
pub use handler::*;
