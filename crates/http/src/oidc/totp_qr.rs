//! The TOTP setup page's QR code: the `otpauth` key URI, as
//! `OTPPolicy.getKeyURI` builds it, drawn as `QRCodeUtils` draws it with
//! zxing's `QRCodeWriter`: error correction level L, one segment, a
//! four-module quiet zone, scaled by a whole number into a 246-pixel square
//! and centered, then written as a one-bit grayscale PNG.
//!
//! Checked by `tests/reference/totp-qr-observations.json`, which compares
//! the codes by what they hold, read by `tests/qr_code.py`.

use qrcodegen::{QrCode, QrCodeEcc, QrSegment, Version};
use rs_keycloak_protocols::totp;

/// The side of the drawn square in pixels, as `TotpUtils.qrCode` asks.
const SIDE: usize = 246;

/// The quiet zone around the code in modules, as zxing's default.
const QUIET_ZONE: usize = 4;

/// Encodes a value as Java's `URLEncoder.encode` does in UTF-8: letters,
/// digits and `.-*_` stay, a space becomes `+`, other bytes `%XX`.
fn url_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'*' | b'_' => {
                encoded.push(char::from(byte));
            }
            b' ' => encoded.push('+'),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

/// The key URI of a TOTP secret: `issuer` is the realm's resolved display
/// name, else its name, and `account` the username.
pub(super) fn key_uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    // ':' separates issuer and account in the label, so it becomes a space.
    let issuer = url_encode(&issuer.replace(':', " ")).replace('+', "%20");
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret}&digits={digits}&algorithm=SHA1&issuer={issuer}&period={period}",
        account = url_encode(account),
        secret = totp::base32(secret),
        digits = totp::DIGITS,
        period = totp::PERIOD,
    )
}

/// Draws `text` as a QR code PNG, or `None` if it does not fit.
pub(super) fn png(text: &str) -> Option<Vec<u8>> {
    let segments = QrSegment::make_segments(text);
    // zxing keeps level L rather than raising it when the version allows.
    let code = QrCode::encode_segments_advanced(
        &segments,
        QrCodeEcc::Low,
        Version::MIN,
        Version::MAX,
        None,
        false,
    )
    .ok()?;
    let modules = usize::try_from(code.size()).ok()?;
    let with_zone = modules + 2 * QUIET_ZONE;
    let side = SIDE.max(with_zone);
    let scale = side / with_zone;
    let padding = (side - modules * scale) / 2;
    // One bit per pixel, white set, rows padded to whole bytes.
    let row_bytes = side.div_ceil(8);
    let mut pixels = vec![0xFF_u8; row_bytes * side];
    for y in 0..modules {
        for x in 0..modules {
            let dark = code.get_module(i32::try_from(x).ok()?, i32::try_from(y).ok()?);
            if !dark {
                continue;
            }
            for row in padding + y * scale..padding + (y + 1) * scale {
                for column in padding + x * scale..padding + (x + 1) * scale {
                    pixels[row * row_bytes + column / 8] &= !(0x80 >> (column % 8));
                }
            }
        }
    }
    let mut image = Vec::new();
    let side = u32::try_from(side).ok()?;
    let mut encoder = png::Encoder::new(&mut image, side, side);
    encoder.set_color(png::ColorType::Grayscale);
    encoder.set_depth(png::BitDepth::One);
    let mut writer = encoder.write_header().ok()?;
    writer.write_image_data(&pixels).ok()?;
    writer.finish().ok()?;
    Some(image)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_uri_encodes_as_the_reference() {
        let uri = key_uri("A:B & C+D/é", "name+tag@example.invalid", b"secret");
        assert_eq!(
            uri,
            "otpauth://totp/A%20B%20%26%20C%2BD%2F%C3%A9:name%2Btag%40example.invalid?secret=ONSWG4TFOQ&digits=6&algorithm=SHA1&issuer=A%20B%20%26%20C%2BD%2F%C3%A9&period=30"
        );
    }

    #[test]
    fn png_is_a_square_one_bit_image() {
        let image = png("otpauth://totp/Realm:user?secret=X").expect("drawn");
        assert_eq!(&image[..8], b"\x89PNG\r\n\x1a\n");
        // IHDR: width, height, bit depth 1, grayscale.
        assert_eq!(&image[16..26], &[0, 0, 0, 246, 0, 0, 0, 246, 1, 0]);
    }
}
