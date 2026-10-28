//! What an upload is, read from its header only: the type from its magic
//! bytes (the name and Content-Type are never trusted), the size and the
//! frame count, before any pixel is decoded.

use std::io::Cursor;

use image::{ImageFormat, ImageReader};

use crate::{MAX_BYTES, MAX_FRAMES, MAX_SIDE, MAX_WORK, Refusal};

/// A picture type we decode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Format {
    /// JPEG.
    Jpeg,
    /// PNG.
    Png,
    /// GIF.
    Gif,
    /// WebP.
    WebP,
    /// BMP.
    Bmp,
    /// TIFF.
    Tiff,
}

impl Format {
    pub(crate) fn image(self) -> ImageFormat {
        match self {
            Self::Jpeg => ImageFormat::Jpeg,
            Self::Png => ImageFormat::Png,
            Self::Gif => ImageFormat::Gif,
            Self::WebP => ImageFormat::WebP,
            Self::Bmp => ImageFormat::Bmp,
            Self::Tiff => ImageFormat::Tiff,
        }
    }
}

/// What the header says.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Info {
    /// The type.
    pub format: Format,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Frames (1 unless a GIF).
    pub frames: usize,
}

fn kind(data: &[u8]) -> Result<Format, Refusal> {
    let starts = |magic: &[u8]| data.starts_with(magic);
    if starts(&[0xFF, 0xD8, 0xFF]) {
        return Ok(Format::Jpeg);
    }
    if starts(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Ok(Format::Png);
    }
    if starts(b"GIF87a") || starts(b"GIF89a") {
        return Ok(Format::Gif);
    }
    if data.len() >= 12 && starts(b"RIFF") && &data[8..12] == b"WEBP" {
        return Ok(Format::WebP);
    }
    if starts(b"BM") {
        return Ok(Format::Bmp);
    }
    if starts(&[0x49, 0x49, 0x2A, 0x00]) || starts(&[0x4D, 0x4D, 0x00, 0x2A]) {
        return Ok(Format::Tiff);
    }
    if data.len() >= 12 && &data[4..8] == b"ftyp" {
        return Err(box_brand(data));
    }
    // XML or HTML-looking text, after a byte order mark and spaces: SVG.
    let text = data.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(data);
    if text
        .iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| *byte == b'<')
    {
        return Err(Refusal::Svg);
    }
    Err(Refusal::Unsupported)
}

/// An ISO base media file: HEIC is named, AVIF is not decoded here yet.
fn box_brand(data: &[u8]) -> Refusal {
    let size = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let end = size.clamp(12, data.len().min(256));
    let brands = std::iter::once(&data[8..12]).chain(data[16.min(end)..end].chunks_exact(4));
    let mut heic = false;
    for brand in brands {
        match brand {
            b"heic" | b"heix" | b"hevc" | b"hevx" | b"heim" | b"heis" => heic = true,
            _ => {}
        }
    }
    if heic {
        Refusal::Heic
    } else {
        Refusal::Unsupported
    }
}

fn frames(format: Format, data: &[u8]) -> Result<usize, Refusal> {
    match format {
        Format::Gif => {
            let mut decoder = gif::DecodeOptions::new()
                .read_info(Cursor::new(data))
                .map_err(|_| Refusal::Decode)?;
            let mut count = 0;
            while decoder
                .next_frame_info()
                .map_err(|_| Refusal::Decode)?
                .is_some()
            {
                count += 1;
                if count > MAX_FRAMES {
                    break;
                }
            }
            Ok(count)
        }
        Format::WebP => {
            let decoder =
                image_webp::WebPDecoder::new(Cursor::new(data)).map_err(|_| Refusal::Decode)?;
            Ok(if decoder.is_animated() {
                decoder.num_frames() as usize
            } else {
                1
            })
        }
        _ => Ok(1),
    }
}

/// Checks `data` against the limits, reading only its header. The caller has
/// already bounded how much it read; this refuses over [`MAX_BYTES`] too.
pub fn inspect(data: &[u8]) -> Result<Info, Refusal> {
    if data.len() > MAX_BYTES {
        return Err(Refusal::TooLarge);
    }
    let format = kind(data)?;
    let (width, height) = ImageReader::with_format(Cursor::new(data), format.image())
        .into_dimensions()
        .map_err(|_| Refusal::Decode)?;
    if width == 0 || height == 0 || width > MAX_SIDE || height > MAX_SIDE {
        return Err(Refusal::Dimensions);
    }
    let frames = frames(format, data)?;
    if frames == 0 {
        return Err(Refusal::Decode);
    }
    if frames > MAX_FRAMES {
        return Err(Refusal::Frames);
    }
    if u64::from(width) * u64::from(height) * frames as u64 > MAX_WORK && frames > 1 {
        return Err(Refusal::Work);
    }
    Ok(Info {
        format,
        width,
        height,
        frames,
    })
}
