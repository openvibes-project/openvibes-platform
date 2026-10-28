#![forbid(unsafe_code)]

//! Profile pictures (roles spec 2026-10-16 §9.2): what a person uploads is
//! checked from its header, decoded, cropped to a square and re-encoded as
//! two WebP images (256 and 64 px; a GIF stays animated). Decoding runs in
//! the `openvibes-picture` helper, one process per upload, under the limits
//! of `openvibes-picture@.service` (no network, 256 MiB, 10 s of CPU, nothing
//! writable). The original is never kept, so no metadata can survive.

#[cfg(feature = "decode")]
mod convert;
#[cfg(feature = "decode")]
mod inspect;
pub mod wire;

#[cfg(feature = "decode")]
pub use convert::convert;
#[cfg(feature = "decode")]
pub use inspect::{Format, Info, inspect};

use serde::{Deserialize, Serialize};

/// Most bytes of an uploaded picture.
pub const MAX_BYTES: usize = 10 * 1024 * 1024;
/// Most pixels along either side.
pub const MAX_SIDE: u32 = 4096;
/// Most frames of an animated picture.
pub const MAX_FRAMES: usize = 300;
/// The large and small sides of the stored images.
pub const LARGE: u32 = 256;
/// See [`LARGE`].
pub const SMALL: u32 = 64;
/// Most pixels over all frames of an animation (width x height x frames):
/// decoding one costs about 15 ns a pixel, so this stays well inside the
/// 10 s of CPU the service allows.
pub const MAX_WORK: u64 = 200_000_000;
/// Most bytes of the stored large image.
pub const MAX_OUTPUT: usize = 3 * 1024 * 1024;

/// The two stored images.
#[derive(Debug, Eq, PartialEq)]
pub struct Output {
    /// 256 px WebP.
    pub large: Vec<u8>,
    /// 64 px WebP.
    pub small: Vec<u8>,
    /// Whether they are animated.
    pub animated: bool,
}

/// The square taken from the original, in its pixels.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Crop {
    /// Left edge.
    pub x: u32,
    /// Top edge.
    pub y: u32,
    /// Side of the square.
    pub size: u32,
}

/// Why a picture was not accepted.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    /// Over [`MAX_BYTES`].
    TooLarge,
    /// Not a picture type we take.
    Unsupported,
    /// SVG is always refused.
    Svg,
    /// HEIC must be converted first.
    Heic,
    /// Over [`MAX_SIDE`] or empty.
    Dimensions,
    /// Over [`MAX_FRAMES`].
    Frames,
    /// An animation with more pixels in all than [`MAX_WORK`].
    Work,
    /// The crop is not a square inside the picture.
    Crop,
    /// The file is damaged or not what its header says.
    Decode,
    /// The result is over [`MAX_OUTPUT`].
    Output,
}

impl Refusal {
    /// The problem code the console answers with.
    pub fn code(self) -> &'static str {
        match self {
            Self::TooLarge => "picture_too_large",
            Self::Unsupported => "picture_unsupported",
            Self::Svg => "picture_svg",
            Self::Heic => "picture_heic",
            Self::Dimensions => "picture_dimensions",
            Self::Frames => "picture_frames",
            Self::Work => "picture_work",
            Self::Crop => "picture_crop",
            Self::Decode => "picture_decode",
            Self::Output => "picture_output",
        }
    }

    /// The words shown to the person.
    pub fn message(self) -> &'static str {
        match self {
            Self::TooLarge => "Use a picture of at most 10 MB",
            Self::Unsupported => "Use a JPEG, PNG, GIF, WebP, BMP or TIFF picture",
            Self::Svg => "SVG pictures are not accepted",
            Self::Heic => "Convert it to JPEG or PNG first",
            Self::Dimensions => "Use a picture of at most 4096 by 4096 pixels",
            Self::Frames => "Use an animation of at most 300 frames",
            Self::Work => "Use a smaller animation, or a still picture",
            Self::Crop => "Choose a square inside the picture",
            Self::Decode => "That file could not be read as a picture",
            Self::Output => "That picture is too detailed; use a simpler or still one",
        }
    }
}
