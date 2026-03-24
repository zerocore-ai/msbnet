//! Secrets intercept handler — substitutes placeholders with real secret values.
//!
//! Implements the [`InterceptHandler`](crate::tls::InterceptHandler) trait to
//! scan TLS plaintext for secret placeholders and substitute real values when
//! the destination matches an allowed host.
//!
//! Substitution is **scoped** by the [`SecretInjection`] config on each entry:
//! the handler splits each chunk on the HTTP header/body boundary (`\r\n\r\n`)
//! and only replaces placeholders in the regions the config allows. Chunks
//! without a boundary are treated as body data (continuation reads).
//!
//! ## Performance
//!
//! The handler is optimised for the properties of this system:
//!
//! - **Single scan**: all placeholder matches in a region are found in one
//!   pass over the bytes, regardless of how many secrets are configured.
//! - **First-byte filter**: a 256-bit set pre-computed at construction skips
//!   every byte that cannot start any placeholder. Since `$` (the common
//!   first byte) is rare in HTTP, almost all positions are skipped with a
//!   single bit-test.
//! - **Single allocation**: the output buffer is sized exactly once from the
//!   collected match list. No intermediate `Vec`s are created per-secret.
//! - **Zero-alloc fast path**: chunks with no matching first byte return
//!   immediately, copying the input as-is.

use std::{borrow::Cow, net::SocketAddr};

use super::config::{SecretEntry, SecretInjection, SecretViolationAction, SecretsConfig};

#[cfg(feature = "tls")]
use crate::tls::InterceptHandler;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// The HTTP header/body separator.
const HEADER_BODY_SEPARATOR: &[u8] = b"\r\n\r\n";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Intercept handler that performs placeholder-based secret substitution.
///
/// For each intercepted TLS connection, scans outbound plaintext for known
/// placeholder strings. If the destination (SNI) matches the secret's allowed
/// hosts, the placeholder is replaced with the real value — but only in the
/// regions permitted by the secret's [`SecretInjection`] config.
///
/// ## Algorithm
///
/// Substitution runs in three phases on each TLS plaintext chunk:
///
/// 1. **Scan** — walk the bytes once, collecting every placeholder occurrence
///    and its position. A 256-bit first-byte mask (`first_byte_mask`) lets
///    the loop skip any byte that cannot start a placeholder with a single
///    bit-test. Standard placeholders start with `$`, which is rare in HTTP,
///    so the scanner skips almost every position in a 16 KB chunk.
///
/// 2. **Validate** — check every collected match against the host allowlist
///    *before* performing any replacement. This is intentional: if even one
///    match targets an unauthorized host, the entire chunk is rejected. No
///    partial substitution can leak a real value alongside a violation.
///
/// 3. **Build** — compute the exact output size from the match list and
///    assemble the result in a single allocation. Bytes between matches are
///    copied verbatim; matched ranges are replaced with the corresponding
///    secret value. No intermediate `Vec`s are created per-secret.
///
/// Must be constructed via [`SecretsHandler::new`] — the first-byte mask is
/// derived from the configured placeholders and would be incorrect if the
/// struct were built with a literal.
pub struct SecretsHandler {
    /// Secret entries with placeholders and allowlists.
    secrets: Vec<SecretEntry>,

    /// Action on violation (placeholder going to unauthorized host).
    on_violation: SecretViolationAction,

    /// Whether to block substitution for TLS-bypassed domains.
    ///
    /// Reserved for future integration with the TLS bypass path — the proxy
    /// would consult this flag before calling the handler for bypassed
    /// domains.
    #[allow(dead_code)]
    block_on_tls_bypass: bool,

    /// Bit-set indexed by byte value (0–255). A set bit means at least one
    /// placeholder starts with that byte. Laid out as four `u64`s covering
    /// the full 256-bit range: `mask[byte / 64] & (1 << (byte % 64))`.
    ///
    /// At scan time, every byte in the chunk is tested against this mask.
    /// A miss (the overwhelmingly common case) costs one array lookup and
    /// one bitwise-AND — the branch predictor learns this quickly and the
    /// loop runs at near-memcpy speed through non-candidate regions.
    first_byte_mask: [u64; 4],
}

/// A single placeholder match found during scanning.
struct Match {
    /// Byte offset within the original `data` slice.
    pos: usize,
    /// Index into [`SecretsHandler::secrets`].
    secret_idx: usize,
    /// Length of the matched placeholder in bytes.
    placeholder_len: usize,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SecretsHandler {
    /// Creates a new secrets handler from the serialized config.
    pub fn new(config: &SecretsConfig) -> Self {
        let secrets = config.secrets.clone();
        let first_byte_mask = build_first_byte_mask(&secrets);

        Self {
            secrets,
            on_violation: config.on_violation.clone(),
            block_on_tls_bypass: config.block_on_tls_bypass,
            first_byte_mask,
        }
    }

    /// Returns `true` if this handler has any secrets configured.
    pub fn has_secrets(&self) -> bool {
        !self.secrets.is_empty()
    }

    /// Check if a host is allowed for a given secret entry.
    fn is_host_allowed(entry: &SecretEntry, sni: &str) -> bool {
        entry.allowed_hosts.iter().any(|pattern| pattern.matches(sni))
    }

    /// Returns `true` if `byte` can start at least one placeholder.
    #[inline]
    fn is_candidate(&self, byte: u8) -> bool {
        let idx = byte as usize;
        self.first_byte_mask[idx / 64] & (1 << (idx % 64)) != 0
    }

    /// Perform scoped placeholder substitution on a byte buffer.
    ///
    /// The chunk is first split on the `\r\n\r\n` HTTP header/body boundary.
    /// Each region is scanned independently — a secret's [`SecretInjection`]
    /// config determines which regions it is eligible for. Chunks without a
    /// boundary are treated entirely as body (a continuation read after the
    /// headers were delivered in a prior chunk).
    ///
    /// Returns `Ok(Cow::Borrowed(data))` when no substitution occurred
    /// (zero-copy), `Ok(Cow::Owned(output))` with substituted bytes, or
    /// `Err(action)` if a violation was detected.
    ///
    /// See the [struct-level docs](SecretsHandler) for the three-phase
    /// algorithm (scan → validate → build).
    fn substitute<'a>(
        &self,
        sni: &str,
        data: &'a [u8],
    ) -> Result<Cow<'a, [u8]>, &SecretViolationAction> {
        let (headers, body) = split_header_body(data);

        // Pre-check: does any secret allow header / body injection?
        // This restores the short-circuit behaviour that avoids scanning
        // an entire region when no secret is eligible for it.
        let any_header = self
            .secrets
            .iter()
            .any(|e| Region::Headers.allowed_by(&e.injection));
        let any_body = self
            .secrets
            .iter()
            .any(|e| Region::Body.allowed_by(&e.injection));

        // --- Phase 1: scan ---------------------------------------------------------------
        //
        // Walk each region once, collecting every (position, secret) pair.
        // The `offset` parameter translates region-local positions back to
        // positions in the original `data` slice so that Phase 3 can index
        // directly into `data`. Regions where no secret is eligible are
        // skipped entirely — no bytes are touched.
        let mut matches: Vec<Match> = Vec::new();

        if !headers.is_empty() && any_header {
            self.scan_region(headers, 0, Region::Headers, &mut matches);
        }
        if !body.is_empty() && any_body {
            self.scan_region(body, headers.len(), Region::Body, &mut matches);
        }

        // Fast path: no placeholders anywhere in the chunk — zero-copy.
        if matches.is_empty() {
            return Ok(Cow::Borrowed(data));
        }

        // --- Phase 2: validate -----------------------------------------------------------
        //
        // Check *all* matches before performing *any* replacement. This
        // prevents a partially-substituted chunk from being sent when a
        // later match is a violation. Either every placeholder in the chunk
        // is authorized, or the entire chunk is rejected.
        for m in &matches {
            let entry = &self.secrets[m.secret_idx];
            if !Self::is_host_allowed(entry, sni) {
                return Err(&self.on_violation);
            }
        }

        // --- Phase 3: build --------------------------------------------------------------
        //
        // Pre-compute the exact output length so the Vec allocates once.
        // Then stitch the output from alternating verbatim spans (bytes
        // between matches) and replacement values.
        let size_delta: isize = matches
            .iter()
            .map(|m| {
                self.secrets[m.secret_idx].value.len() as isize - m.placeholder_len as isize
            })
            .sum();
        let output_len = (data.len() as isize + size_delta) as usize;

        let mut output = Vec::with_capacity(output_len);
        let mut cursor = 0usize;

        for m in &matches {
            output.extend_from_slice(&data[cursor..m.pos]);
            output.extend_from_slice(self.secrets[m.secret_idx].value.as_bytes());
            cursor = m.pos + m.placeholder_len;
        }
        output.extend_from_slice(&data[cursor..]);

        debug_assert_eq!(output.len(), output_len);
        Ok(Cow::Owned(output))
    }

    /// Scan a single region (headers or body) for placeholder matches.
    ///
    /// Walks the region byte-by-byte. At each position the first-byte mask
    /// is tested — if the current byte cannot start any placeholder, the
    /// position is skipped immediately (one array lookup + one AND). When a
    /// candidate byte is found, the loop checks each secret's placeholder
    /// with a slice comparison, filtering out secrets whose injection config
    /// does not cover this region.
    ///
    /// Matches are recorded with positions translated to the original `data`
    /// slice via `offset`. When a placeholder matches, the scan jumps past
    /// it (non-overlapping), so no position is examined twice.
    fn scan_region(
        &self,
        region: &[u8],
        offset: usize,
        kind: Region,
        matches: &mut Vec<Match>,
    ) {
        let mut pos = 0;

        while pos < region.len() {
            // Fast skip: test the first-byte mask.
            if !self.is_candidate(region[pos]) {
                pos += 1;
                continue;
            }

            // Candidate byte — check each secret's placeholder.
            let mut matched = false;
            for (idx, entry) in self.secrets.iter().enumerate() {
                // Check injection scoping before comparing bytes.
                if !kind.allowed_by(&entry.injection) {
                    continue;
                }

                let ph = entry.placeholder.as_bytes();
                if region.len() - pos >= ph.len() && region[pos..pos + ph.len()] == *ph {
                    matches.push(Match {
                        pos: pos + offset,
                        secret_idx: idx,
                        placeholder_len: ph.len(),
                    });
                    // Skip past the matched placeholder (non-overlapping).
                    pos += ph.len();
                    matched = true;
                    break;
                }
            }

            if !matched {
                pos += 1;
            }
        }
    }
}

/// Which region of an HTTP message a scan covers.
///
/// The TLS proxy reads fixed-size chunks (typically 16 KB). The first chunk
/// of a request almost always contains the full HTTP headers followed by
/// `\r\n\r\n`. Subsequent chunks are body continuations with no separator.
///
/// - **Chunk has `\r\n\r\n`**: bytes before it → [`Headers`], bytes after → [`Body`].
/// - **Chunk has no `\r\n\r\n`**: entire chunk → [`Body`] (continuation read).
///
/// This means a secret with `body: false` is never substituted in
/// continuation chunks, which is the desired default behaviour.
enum Region {
    Headers,
    Body,
}

impl Region {
    /// Returns `true` if the secret's injection config allows substitution
    /// in this region.
    ///
    /// The header region covers the request line (which contains query
    /// parameters), all header fields (which contains `Authorization` for
    /// basic auth), and the terminating blank line. Any of `headers`,
    /// `basic_auth`, or `query_params` enables scanning this entire region
    /// — finer-grained header parsing is not performed.
    fn allowed_by(&self, injection: &SecretInjection) -> bool {
        match self {
            Self::Headers => injection.headers || injection.basic_auth || injection.query_params,
            Self::Body => injection.body,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "tls")]
impl InterceptHandler for SecretsHandler {
    fn on_request<'a>(&self, _dst: &SocketAddr, sni: &str, data: &'a [u8]) -> Cow<'a, [u8]> {
        match self.substitute(sni, data) {
            Ok(cow) => cow,
            Err(action) => match action {
                SecretViolationAction::Block => Cow::Owned(Vec::new()),
                SecretViolationAction::BlockAndLog => {
                    tracing::warn!(
                        sni,
                        "secret violation: placeholder detected in request to unauthorized host"
                    );
                    Cow::Owned(Vec::new())
                }
                SecretViolationAction::BlockAndTerminate => {
                    tracing::error!(
                        sni,
                        "secret violation: placeholder detected in request to unauthorized host — terminating"
                    );
                    std::process::exit(1);
                }
            },
        }
    }

    fn on_response<'a>(&self, _dst: &SocketAddr, _sni: &str, data: &'a [u8]) -> Cow<'a, [u8]> {
        // The sandbox never has real secret values — zero-copy pass-through.
        Cow::Borrowed(data)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Build a 256-bit set of byte values that are the first byte of at least
/// one placeholder string. Used by [`SecretsHandler::is_candidate`].
fn build_first_byte_mask(secrets: &[SecretEntry]) -> [u64; 4] {
    let mut mask = [0u64; 4];
    for entry in secrets {
        if let Some(&b) = entry.placeholder.as_bytes().first() {
            let idx = b as usize;
            mask[idx / 64] |= 1 << (idx % 64);
        }
    }
    mask
}

/// Split a chunk into header and body regions.
///
/// If the chunk contains `\r\n\r\n`, everything up to and including the
/// separator is the header region, and the rest is body. If no separator is
/// found, the chunk is treated as body data (a continuation read after the
/// headers were already sent in a prior chunk).
fn split_header_body(data: &[u8]) -> (&[u8], &[u8]) {
    if let Some(pos) = data
        .windows(HEADER_BODY_SEPARATOR.len())
        .position(|w| w == HEADER_BODY_SEPARATOR)
    {
        let boundary = pos + HEADER_BODY_SEPARATOR.len();
        (&data[..boundary], &data[boundary..])
    } else {
        (&[], data)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::config::HostPattern;

    fn make_entry_with_injection(
        placeholder: &str,
        value: &str,
        hosts: Vec<HostPattern>,
        injection: SecretInjection,
    ) -> SecretEntry {
        SecretEntry {
            placeholder: placeholder.into(),
            value: value.into(),
            allowed_hosts: hosts,
            injection,
            require_tls_identity: true,
        }
    }

    fn make_entry(placeholder: &str, value: &str, hosts: Vec<HostPattern>) -> SecretEntry {
        make_entry_with_injection(placeholder, value, hosts, SecretInjection::default())
    }

    fn make_handler(secrets: Vec<SecretEntry>, action: SecretViolationAction) -> SecretsHandler {
        SecretsHandler::new(&SecretsConfig {
            secrets,
            on_violation: action,
            block_on_tls_bypass: true,
        })
    }

    // -- first-byte mask --

    #[test]
    fn test_first_byte_mask_standard_placeholder() {
        let handler = make_handler(
            vec![make_entry("$MSB_abc", "v", vec![HostPattern::Any])],
            SecretViolationAction::Block,
        );
        assert!(handler.is_candidate(b'$'));
        assert!(!handler.is_candidate(b'A'));
        assert!(!handler.is_candidate(b'\r'));
    }

    #[test]
    fn test_first_byte_mask_custom_placeholder() {
        let handler = make_handler(
            vec![
                make_entry("$MSB_abc", "v1", vec![HostPattern::Any]),
                make_entry("{{TOKEN}}", "v2", vec![HostPattern::Any]),
            ],
            SecretViolationAction::Block,
        );
        assert!(handler.is_candidate(b'$'));
        assert!(handler.is_candidate(b'{'));
        assert!(!handler.is_candidate(b'A'));
    }

    // -- split_header_body --

    #[test]
    fn test_split_header_body_with_boundary() {
        let data = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody here";
        let (h, b) = split_header_body(data);
        assert_eq!(h, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(b, b"body here");
    }

    #[test]
    fn test_split_header_body_no_body() {
        let data = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let (h, b) = split_header_body(data);
        assert_eq!(h, data.as_slice());
        assert!(b.is_empty());
    }

    #[test]
    fn test_split_header_body_no_boundary_is_body() {
        let data = b"continuation body data";
        let (h, b) = split_header_body(data);
        assert!(h.is_empty());
        assert_eq!(b, data.as_slice());
    }

    // -- scoped substitution --

    #[test]
    fn test_substitute_header_only_default_injection() {
        let handler = make_handler(
            vec![make_entry(
                "$MSB_abc",
                "sk-real",
                vec![HostPattern::Exact("api.openai.com".into())],
            )],
            SecretViolationAction::Block,
        );

        let data = b"Authorization: Bearer $MSB_abc\r\n\r\n{\"key\":\"$MSB_abc\"}";
        let result = handler.substitute("api.openai.com", data).unwrap();
        assert_eq!(
            result.as_ref(),
            b"Authorization: Bearer sk-real\r\n\r\n{\"key\":\"$MSB_abc\"}"
        );
    }

    #[test]
    fn test_substitute_body_enabled() {
        let injection = SecretInjection {
            headers: true,
            basic_auth: true,
            query_params: false,
            body: true,
        };
        let handler = make_handler(
            vec![make_entry_with_injection(
                "$MSB_abc",
                "sk-real",
                vec![HostPattern::Exact("host.com".into())],
                injection,
            )],
            SecretViolationAction::Block,
        );

        let data = b"X-Key: $MSB_abc\r\n\r\n{\"key\":\"$MSB_abc\"}";
        let result = handler.substitute("host.com", data).unwrap();
        assert_eq!(result.as_ref(), b"X-Key: sk-real\r\n\r\n{\"key\":\"sk-real\"}");
    }

    #[test]
    fn test_substitute_headers_disabled() {
        let injection = SecretInjection {
            headers: false,
            basic_auth: false,
            query_params: false,
            body: true,
        };
        let handler = make_handler(
            vec![make_entry_with_injection(
                "$MSB_abc",
                "sk-real",
                vec![HostPattern::Exact("host.com".into())],
                injection,
            )],
            SecretViolationAction::Block,
        );

        let data = b"X-Key: $MSB_abc\r\n\r\n{\"key\":\"$MSB_abc\"}";
        let result = handler.substitute("host.com", data).unwrap();
        assert_eq!(
            result.as_ref(),
            b"X-Key: $MSB_abc\r\n\r\n{\"key\":\"sk-real\"}"
        );
    }

    #[test]
    fn test_substitute_continuation_chunk_body_false() {
        let handler = make_handler(
            vec![make_entry(
                "$MSB_abc",
                "sk-real",
                vec![HostPattern::Exact("host.com".into())],
            )],
            SecretViolationAction::Block,
        );

        let data = b"more body with $MSB_abc in it";
        let result = handler.substitute("host.com", data).unwrap();
        assert_eq!(result.as_ref(), data.as_slice());
    }

    #[test]
    fn test_substitute_continuation_chunk_body_true() {
        let injection = SecretInjection {
            body: true,
            ..Default::default()
        };
        let handler = make_handler(
            vec![make_entry_with_injection(
                "$MSB_abc",
                "sk-real",
                vec![HostPattern::Exact("host.com".into())],
                injection,
            )],
            SecretViolationAction::Block,
        );

        let data = b"more body with $MSB_abc in it";
        let result = handler.substitute("host.com", data).unwrap();
        assert_eq!(result.as_ref(), b"more body with sk-real in it");
    }

    // -- violation detection --

    #[test]
    fn test_substitute_unauthorized_host_in_headers() {
        let handler = make_handler(
            vec![make_entry(
                "$MSB_abc",
                "sk-real",
                vec![HostPattern::Exact("api.openai.com".into())],
            )],
            SecretViolationAction::Block,
        );

        let data = b"Authorization: Bearer $MSB_abc\r\n\r\n";
        assert!(handler.substitute("evil.com", data).is_err());
    }

    #[test]
    fn test_substitute_no_placeholder_passthrough() {
        let handler = make_handler(
            vec![make_entry(
                "$MSB_abc",
                "sk-real",
                vec![HostPattern::Exact("api.openai.com".into())],
            )],
            SecretViolationAction::Block,
        );

        let data = b"GET /api/v1/models HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(handler.substitute("anything.com", data).unwrap().as_ref(), data.as_slice());
    }

    // -- multi-secret --

    #[test]
    fn test_substitute_multiple_secrets() {
        let handler = make_handler(
            vec![
                make_entry("$MSB_one", "val1", vec![HostPattern::Exact("host.com".into())]),
                make_entry("$MSB_two", "val2", vec![HostPattern::Exact("host.com".into())]),
            ],
            SecretViolationAction::Block,
        );

        let data = b"X-Key: $MSB_one\r\nX-Other: $MSB_two\r\n\r\n";
        assert_eq!(
            handler.substitute("host.com", data).unwrap().as_ref(),
            b"X-Key: val1\r\nX-Other: val2\r\n\r\n"
        );
    }

    #[test]
    fn test_substitute_wildcard_host() {
        let handler = make_handler(
            vec![make_entry(
                "$MSB_gh",
                "ghp_token",
                vec![HostPattern::Wildcard("*.github.com".into())],
            )],
            SecretViolationAction::Block,
        );

        let data = b"Authorization: token $MSB_gh\r\n\r\n";
        assert_eq!(
            handler.substitute("api.github.com", data).unwrap().as_ref(),
            b"Authorization: token ghp_token\r\n\r\n"
        );
    }

    // -- output sizing --

    #[test]
    fn test_substitute_different_lengths() {
        // Placeholder shorter than value (output grows).
        let handler = make_handler(
            vec![make_entry("$MSB_x", "a-very-long-secret-value", vec![HostPattern::Any])],
            SecretViolationAction::Block,
        );
        let data = b"Auth: $MSB_x\r\n\r\n";
        let result = handler.substitute("any.com", data).unwrap();
        assert_eq!(result.as_ref(), b"Auth: a-very-long-secret-value\r\n\r\n");

        // Placeholder longer than value (output shrinks).
        let handler = make_handler(
            vec![make_entry("$MSB_very_long_placeholder", "k", vec![HostPattern::Any])],
            SecretViolationAction::Block,
        );
        let data = b"Auth: $MSB_very_long_placeholder\r\n\r\n";
        let result = handler.substitute("any.com", data).unwrap();
        assert_eq!(result.as_ref(), b"Auth: k\r\n\r\n");
    }

    #[test]
    fn test_substitute_multiple_occurrences_same_secret() {
        let handler = make_handler(
            vec![make_entry("$MSB_x", "val", vec![HostPattern::Any])],
            SecretViolationAction::Block,
        );
        let data = b"A: $MSB_x\r\nB: $MSB_x\r\n\r\n";
        assert_eq!(
            handler.substitute("any.com", data).unwrap().as_ref(),
            b"A: val\r\nB: val\r\n\r\n"
        );
    }

    // -- has_secrets --

    #[test]
    fn test_has_secrets() {
        let empty = make_handler(vec![], SecretViolationAction::Block);
        assert!(!empty.has_secrets());

        let with = make_handler(
            vec![make_entry("$MSB_x", "v", vec![HostPattern::Any])],
            SecretViolationAction::Block,
        );
        assert!(with.has_secrets());
    }
}
