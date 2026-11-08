//! One-time passwords as the reference's `HmacOTP` and `TimeBasedOTP`:
//! RFC 4226 and RFC 6238 codes over the secret string's bytes, with the
//! algorithm, digits and period of an OTP policy.

use ring::hmac;
use subtle::ConstantTimeEq;

/// The HMAC of an OTP policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    /// `HmacSHA1`, the default.
    Sha1,
    /// `HmacSHA256`.
    Sha256,
    /// `HmacSHA512`.
    Sha512,
}

impl Algorithm {
    /// Reads a policy's Java algorithm name.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "HmacSHA1" => Some(Self::Sha1),
            "HmacSHA256" => Some(Self::Sha256),
            "HmacSHA512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// The name key URIs and the manual setup page use, as
    /// `OTPPolicy.getAlgorithmKey`.
    pub fn key(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    fn ring(self) -> hmac::Algorithm {
        match self {
            Self::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => hmac::HMAC_SHA256,
            Self::Sha512 => hmac::HMAC_SHA512,
        }
    }
}

/// The most digits a code may have; more would exceed the 31-bit value.
pub const MAX_DIGITS: u32 = 10;

/// How codes are computed: the policy's algorithm and digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodeFormat {
    /// The HMAC.
    pub algorithm: Algorithm,
    /// Digits in a code, 1 to [`MAX_DIGITS`].
    pub digits: u32,
}

impl CodeFormat {
    /// Keycloak's default: HMAC-SHA1 with 6 digits.
    pub const DEFAULT: Self = Self {
        algorithm: Algorithm::Sha1,
        digits: 6,
    };

    /// A format from stored policy values, if codes can be made with it.
    pub fn new(algorithm: Option<&str>, digits: i32) -> Option<Self> {
        let digits = u32::try_from(digits)
            .ok()
            .filter(|digits| (1..=MAX_DIGITS).contains(digits))?;
        Some(Self {
            algorithm: Algorithm::parse(algorithm?)?,
            digits,
        })
    }

    /// Computes the code for a counter or time step.
    pub fn code(self, secret: &[u8], counter: u64) -> String {
        let key = hmac::Key::new(self.algorithm.ring(), secret);
        let digest = hmac::sign(&key, &counter.to_be_bytes());
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
            u64::from(value) % 10u64.pow(self.digits),
            width = self.digits as usize
        )
    }

    fn well_formed(self, candidate: &str) -> bool {
        candidate.len() == self.digits as usize
            && candidate.bytes().all(|byte| byte.is_ascii_digit())
    }

    fn matches(self, secret: &[u8], counter: u64, candidate: &str) -> bool {
        self.code(secret, counter)
            .as_bytes()
            .ct_eq(candidate.as_bytes())
            .into()
    }

    /// Returns the time step `candidate` belongs to at `now`, within
    /// `look_around` steps either side, as `TimeBasedOTP.validateTOTP`;
    /// steps in `used` are refused, so a code is accepted once.
    pub fn verify_totp(
        self,
        secret: &[u8],
        candidate: &str,
        now: u64,
        period: u64,
        look_around: u64,
        used: &[i64],
    ) -> Option<u64> {
        if period == 0 || !self.well_formed(candidate) {
            return None;
        }
        let current = now / period;
        let mut accepted = None;
        // Check every step in the window so timing does not reveal which matched.
        for step in current.saturating_sub(look_around)..=current.saturating_add(look_around) {
            let unused = i64::try_from(step).is_ok_and(|step| !used.contains(&step));
            if self.matches(secret, step, candidate) && unused {
                accepted = Some(step);
            }
        }
        accepted
    }

    /// Returns the counter `candidate` belongs to, from `counter` through
    /// `counter + look_ahead`, as `HmacOTP.validateHOTP`.
    pub fn verify_hotp(
        self,
        secret: &[u8],
        candidate: &str,
        counter: u64,
        look_ahead: u64,
    ) -> Option<u64> {
        if !self.well_formed(candidate) {
            return None;
        }
        let mut accepted = None;
        for next in counter..=counter.saturating_add(look_ahead) {
            if self.matches(secret, next, candidate) && accepted.is_none() {
                accepted = Some(next);
            }
        }
        accepted
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
mod tests {
    use super::{Algorithm, CodeFormat, base32};

    // RFC 6238 appendix B: the seed for each HMAC, 8 digits.
    const SHA1: &[u8] = b"12345678901234567890";
    const SHA256: &[u8] = b"12345678901234567890123456789012";
    const SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    fn format(algorithm: Algorithm, digits: u32) -> CodeFormat {
        CodeFormat { algorithm, digits }
    }

    #[test]
    fn matches_rfc_6238_vectors() {
        for (time, sha1, sha256, sha512) in [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ] {
            let step = time / 30;
            assert_eq!(format(Algorithm::Sha1, 8).code(SHA1, step), sha1);
            assert_eq!(format(Algorithm::Sha256, 8).code(SHA256, step), sha256);
            assert_eq!(format(Algorithm::Sha512, 8).code(SHA512, step), sha512);
        }
        assert_eq!(CodeFormat::DEFAULT.code(SHA1, 59 / 30), "287082");
    }

    #[test]
    fn totp_accepts_the_window_once() {
        let now = 1_234_567_890;
        let step = now / 30;
        let code = |step| CodeFormat::DEFAULT.code(SHA1, step);
        let verify = |candidate: &str, look_around, used: &[i64]| {
            CodeFormat::DEFAULT.verify_totp(SHA1, candidate, now, 30, look_around, used)
        };
        assert_eq!(verify(&code(step), 1, &[]), Some(step));
        assert_eq!(verify(&code(step - 1), 1, &[]), Some(step - 1));
        assert_eq!(verify(&code(step - 1), 0, &[]), None);
        assert_eq!(verify(&code(step - 2), 1, &[]), None);
        let used = [i64::try_from(step).unwrap()];
        assert_eq!(verify(&code(step), 1, &used), None);
        assert_eq!(verify(&code(step - 1), 1, &used), Some(step - 1));
        assert_eq!(verify("12345", 1, &[]), None);
        assert_eq!(verify("abcdef", 1, &[]), None);
    }

    #[test]
    fn hotp_looks_ahead_from_the_counter() {
        let code = |counter| CodeFormat::DEFAULT.code(SHA1, counter);
        let verify = |candidate: &str| CodeFormat::DEFAULT.verify_hotp(SHA1, candidate, 5, 2);
        assert_eq!(verify(&code(5)), Some(5));
        assert_eq!(verify(&code(7)), Some(7));
        assert_eq!(verify(&code(8)), None);
        assert_eq!(verify(&code(4)), None);
    }

    #[test]
    fn formats_need_a_known_algorithm_and_digits() {
        assert_eq!(
            CodeFormat::new(Some("HmacSHA1"), 6),
            Some(CodeFormat::DEFAULT)
        );
        assert_eq!(CodeFormat::new(None, 6), None);
        assert_eq!(CodeFormat::new(Some("HmacMD5"), 6), None);
        assert_eq!(CodeFormat::new(Some("HmacSHA1"), 0), None);
        assert_eq!(CodeFormat::new(Some("HmacSHA1"), 11), None);
    }

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
