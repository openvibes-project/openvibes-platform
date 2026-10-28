//! Decoding, cropping and re-encoding. Runs in the helper process only.

use std::io::Cursor;

use image::{
    AnimationDecoder, DynamicImage, ImageDecoder, ImageReader, Limits, RgbaImage,
    codecs::gif::GifDecoder,
    imageops::{self, FilterType},
    metadata::Orientation,
};
use webp_animation::{Encoder, EncoderOptions, EncodingConfig, EncodingType, LossyEncodingConfig};

use crate::{Crop, Format, LARGE, MAX_OUTPUT, MAX_SIDE, Output, Refusal, SMALL, inspect};

fn options() -> EncoderOptions {
    EncoderOptions {
        encoding_config: Some(EncodingConfig {
            quality: 80.0,
            encoding_type: EncodingType::Lossy(LossyEncodingConfig::default()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Crops the square out of an RGBA picture and scales it to `side`.
fn square(image: &RgbaImage, crop: Crop, side: u32, filter: FilterType) -> RgbaImage {
    let cropped = imageops::crop_imm(image, crop.x, crop.y, crop.size, crop.size).to_image();
    if crop.size == side {
        cropped
    } else {
        imageops::resize(&cropped, side, side, filter)
    }
}

fn encoder(side: u32) -> Result<Encoder, Refusal> {
    Encoder::new_with_options((side, side), options()).map_err(|_| Refusal::Decode)
}

/// A browser shows a GIF delay of 10 ms or less as 100 ms.
fn delay_ms(frame: &image::Frame) -> i32 {
    let (numerator, denominator) = frame.delay().numer_denom_ms();
    let ms = (numerator / denominator.max(1)).clamp(0, 60_000);
    if ms <= 10 { 100 } else { ms as i32 }
}

/// Crops and re-encodes `data` as a large and a small WebP.
pub fn convert(data: &[u8], crop: Crop) -> Result<Output, Refusal> {
    let info = inspect(data)?;
    let inside =
        |edge: u32, extent: u32| edge.checked_add(crop.size).is_some_and(|end| end <= extent);
    if crop.size == 0 || !inside(crop.x, info.width) || !inside(crop.y, info.height) {
        return Err(Refusal::Crop);
    }
    let mut large = encoder(LARGE)?;
    let mut small = encoder(SMALL)?;
    let animated = info.format == Format::Gif && info.frames > 1;
    let finish;
    if animated {
        let decoder = GifDecoder::new(Cursor::new(data)).map_err(|_| Refusal::Decode)?;
        let mut at = 0_i32;
        for frame in decoder.into_frames() {
            let frame = frame.map_err(|_| Refusal::Decode)?;
            let delay = delay_ms(&frame);
            let big = square(frame.buffer(), crop, LARGE, FilterType::Triangle);
            let little = imageops::resize(&big, SMALL, SMALL, FilterType::Triangle);
            large
                .add_frame(big.as_raw(), at)
                .map_err(|_| Refusal::Decode)?;
            small
                .add_frame(little.as_raw(), at)
                .map_err(|_| Refusal::Decode)?;
            at = at.saturating_add(delay);
        }
        finish = at;
    } else {
        let mut reader = ImageReader::with_format(Cursor::new(data), info.format.image());
        let mut limits = Limits::default();
        limits.max_image_width = Some(MAX_SIDE);
        limits.max_image_height = Some(MAX_SIDE);
        limits.max_alloc = Some(192 * 1024 * 1024);
        reader.limits(limits);
        let mut decoder = reader.into_decoder().map_err(|_| Refusal::Decode)?;
        let orientation = decoder.orientation().unwrap_or(Orientation::NoTransforms);
        let mut decoded = DynamicImage::from_decoder(decoder).map_err(|_| Refusal::Decode)?;
        decoded.apply_orientation(orientation);
        // The crop is in the turned picture, as the browser showed it. Copy only the
        // square, straight to 8-bit RGBA, so a 16-bit picture is not copied at 16 bits.
        let rgba = imageops::crop_imm(&decoded, crop.x, crop.y, crop.size, crop.size).to_image();
        drop(decoded);
        let big = if crop.size == LARGE {
            rgba
        } else {
            imageops::resize(&rgba, LARGE, LARGE, FilterType::Lanczos3)
        };
        let little = imageops::resize(&big, SMALL, SMALL, FilterType::Lanczos3);
        large
            .add_frame(big.as_raw(), 0)
            .map_err(|_| Refusal::Decode)?;
        small
            .add_frame(little.as_raw(), 0)
            .map_err(|_| Refusal::Decode)?;
        finish = 1;
    }
    let large = large
        .finalize(finish)
        .map_err(|_| Refusal::Decode)?
        .to_vec();
    let small = small
        .finalize(finish)
        .map_err(|_| Refusal::Decode)?
        .to_vec();
    if large.len() > MAX_OUTPUT {
        return Err(Refusal::Output);
    }
    Ok(Output {
        large,
        small,
        animated,
    })
}
