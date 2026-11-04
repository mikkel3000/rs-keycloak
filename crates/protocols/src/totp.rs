//! Time-based one-time passwords (RFC 6238) with Keycloak's default policy:
//! HMAC-SHA1 over the secret string's bytes, 6 digits, 30-second steps.

use ring::hmac;
use subtle::ConstantTimeEq;

/// Seconds per time step.
pub const PERIOD: u64 = 30;
/// Digits in a code.
pub const DIGITS: u32 = 6;
/// Steps before and after the current one that are still accepted.
pub const LOOK_AROUND: u64 = 1;

/// Computes the code for a time step.
pub fn code(secret: &[u8], step: u64, digits: u32) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let digest = hmac::sign(&key, &step.to_be_bytes());
    let digest = digest.as_ref();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let value = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    format!(
        "{:0width$}",
        value % 10u32.pow(digits),
        width = digits as usize
    )
}

/// Returns the accepted step for `candidate` at `now`, if it is within the
/// look-around window and later than `last_used_step`, which blocks reuse.
pub fn verify(
    secret: &[u8],
    candidate: &str,
    now: u64,
    last_used_step: Option<u64>,
) -> Option<u64> {
    if candidate.len() != DIGITS as usize || !candidate.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let current = now / PERIOD;
    let mut accepted = None;
    // Check every step in the window so timing does not reveal which matched.
    for step in current.saturating_sub(LOOK_AROUND)..=current + LOOK_AROUND {
        let matches: bool = code(secret, step, DIGITS)
            .as_bytes()
            .ct_eq(candidate.as_bytes())
            .into();
        if matches && last_used_step.is_none_or(|last| step > last) {
            accepted = Some(step);
        }
    }
    accepted
}

#[cfg(test)]
mod tests {
    use super::{PERIOD, code, verify};

    // RFC 6238 appendix B, SHA-1 secret, reduced to the 6-digit suffix.
    const SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn matches_rfc_6238_vectors() {
        assert_eq!(code(SECRET, 59 / PERIOD, 8), "94287082");
        assert_eq!(code(SECRET, 1_111_111_109 / PERIOD, 8), "07081804");
        assert_eq!(code(SECRET, 1_234_567_890 / PERIOD, 8), "89005924");
        assert_eq!(code(SECRET, 20_000_000_000 / PERIOD, 8), "65353130");
        assert_eq!(code(SECRET, 59 / PERIOD, 6), "287082");
    }

    #[test]
    fn accepts_adjacent_steps_once() {
        let now = 1_234_567_890;
        let current = code(SECRET, now / PERIOD, 6);
        let previous = code(SECRET, now / PERIOD - 1, 6);
        assert_eq!(verify(SECRET, &current, now, None), Some(now / PERIOD));
        assert_eq!(verify(SECRET, &previous, now, None), Some(now / PERIOD - 1));
        assert_eq!(verify(SECRET, &current, now, Some(now / PERIOD)), None);
        assert_eq!(
            verify(SECRET, &code(SECRET, now / PERIOD - 2, 6), now, None),
            None
        );
        assert_eq!(verify(SECRET, "12345", now, None), None);
        assert_eq!(verify(SECRET, "abcdef", now, None), None);
    }
}

/// Encodes bytes as unpadded RFC 4648 base32, the form authenticator apps
/// read from `otpauth://` URIs.
pub fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            encoded.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        encoded.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    encoded
}

#[cfg(test)]
mod base32_tests {
    use super::base32;

    #[test]
    fn matches_rfc_4648_vectors_without_padding() {
        for (input, expected) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32(input.as_bytes()), expected);
        }
    }
}
