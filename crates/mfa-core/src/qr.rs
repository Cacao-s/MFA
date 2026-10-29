//! Reading a QR code out of an image file or a screen grab.
//!
//! This is the desktop half of "add an account" (spec §1): macOS and Windows
//! have no camera flow worth building, but they can read a screenshot of the
//! QR code the website is showing. Mobile cameras go through
//! [`crate::platform::QrScanner`] instead, because the frame pipeline belongs
//! to the platform.
//!
//! Enabled by the `qr-image` feature.

use crate::error::{Error, Result};

/// Decodes every QR code in an image, returning their payloads as text.
///
/// Decoding is deliberately separate from interpreting: a screen grab may
/// contain several codes, and one of them being unreadable should not hide the
/// others.
pub fn decode_image(bytes: &[u8]) -> Result<Vec<String>> {
    let image = image::load_from_memory(bytes)
        .map_err(|_| Error::UnreadableImage)?
        .to_luma8();
    let (width, height) = (image.width() as usize, image.height() as usize);

    // Going through raw greyscale rather than rqrr's image integration keeps
    // this crate's `image` version independent of rqrr's.
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| {
        image.get_pixel(x as u32, y as u32).0[0]
    });

    let payloads: Vec<String> = prepared
        .detect_grids()
        .into_iter()
        .filter_map(|grid| grid.decode().ok().map(|(_meta, payload)| payload))
        .collect();

    if payloads.is_empty() {
        return Err(Error::NoQrCodeFound);
    }
    Ok(payloads)
}

/// The OTP-related payloads in an image, in the order found.
///
/// Filters out the unrelated codes a full-screen grab tends to pick up.
pub fn decode_otp_uris(bytes: &[u8]) -> Result<Vec<String>> {
    let uris: Vec<String> = decode_image(bytes)?
        .into_iter()
        .filter(|payload| {
            let lower = payload.to_ascii_lowercase();
            lower.starts_with("otpauth://") || lower.starts_with("otpauth-migration://")
        })
        .collect();

    if uris.is_empty() {
        return Err(Error::NoQrCodeFound);
    }
    Ok(uris)
}
