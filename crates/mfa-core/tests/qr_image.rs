//! Desktop "add from an image file or screen grab" (spec §1).
//!
//! The fixtures are rendered by the `qrcode` crate and decoded by `rqrr`, two
//! unrelated implementations, so a pass means the pipeline really works and
//! not that one library agrees with itself.
#![cfg(feature = "qr-image")]

use image::{GenericImage, Luma, RgbaImage};
use mfa_core::qr::{decode_image, decode_otp_uris};
use mfa_core::OtpauthUri;
use qrcode::QrCode;

const URI: &str = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";

/// Renders `payload` as a PNG, the way a screen grab would contain it.
fn qr_png(payload: &str) -> Vec<u8> {
    let code = QrCode::new(payload.as_bytes()).expect("payload fits in a QR code");
    let image = code.render::<Luma<u8>>().min_dimensions(240, 240).build();

    let mut png = Vec::new();
    image
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .expect("in-memory PNG encoding");
    png
}

#[test]
fn reads_an_otpauth_uri_out_of_a_png() {
    let payloads = decode_image(&qr_png(URI)).unwrap();
    assert_eq!(payloads, vec![URI.to_owned()]);

    // And the payload is usable, not just readable.
    let parsed = OtpauthUri::parse(&payloads[0]).unwrap();
    assert_eq!(parsed.account, "alice@example.com");
}

#[test]
fn ignores_unrelated_codes_in_the_same_grab() {
    // A full-screen grab picks up whatever else is on screen.
    let otp = qr_png(URI);
    let other = qr_png("https://example.com/not-a-token");

    let combined = side_by_side(&otp, &other);
    let all = decode_image(&combined).unwrap();
    assert_eq!(all.len(), 2, "both codes should be found");

    let otp_only = decode_otp_uris(&combined).unwrap();
    assert_eq!(otp_only, vec![URI.to_owned()]);
}

#[test]
fn says_so_when_there_is_no_code() {
    let blank = RgbaImage::from_pixel(120, 120, image::Rgba([255, 255, 255, 255]));
    let mut png = Vec::new();
    blank
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .unwrap();

    let error = decode_image(&png).unwrap_err().to_string();
    assert!(error.contains("no QR code"), "unhelpful: {error}");
}

#[test]
fn says_so_when_the_file_is_not_an_image() {
    let error = decode_image(b"this is not a png").unwrap_err().to_string();
    assert!(error.contains("could not be read"), "unhelpful: {error}");
}

/// Pastes two PNGs onto one white canvas, with a gap so the quiet zones hold.
fn side_by_side(left: &[u8], right: &[u8]) -> Vec<u8> {
    let left = image::load_from_memory(left).unwrap().to_rgba8();
    let right = image::load_from_memory(right).unwrap().to_rgba8();

    let gap = 40;
    let width = left.width() + gap + right.width();
    let height = left.height().max(right.height());
    let mut canvas = RgbaImage::from_pixel(width, height, image::Rgba([255, 255, 255, 255]));
    canvas.copy_from(&left, 0, 0).unwrap();
    canvas.copy_from(&right, left.width() + gap, 0).unwrap();

    let mut png = Vec::new();
    canvas
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .unwrap();
    png
}
