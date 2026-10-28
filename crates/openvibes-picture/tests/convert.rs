//! What a picture becomes, and what is refused before any pixel is decoded.

use std::io::Cursor;

use image::{
    Delay, Frame, ImageEncoder, ImageFormat, Rgba, RgbaImage,
    codecs::gif::{GifEncoder, Repeat},
};
use openvibes_picture::{Crop, Format, MAX_BYTES, Refusal, convert, inspect, wire};

fn picture(width: u32, height: u32) -> RgbaImage {
    RgbaImage::from_fn(width, height, |x, y| {
        Rgba([
            (x * 255 / width.max(1)) as u8,
            (y * 255 / height.max(1)) as u8,
            90,
            255,
        ])
    })
}

fn encoded(format: ImageFormat, width: u32, height: u32) -> Vec<u8> {
    let mut out = Cursor::new(Vec::new());
    let image = image::DynamicImage::ImageRgba8(picture(width, height));
    match format {
        // JPEG has no alpha.
        ImageFormat::Jpeg => image.to_rgb8().write_to(&mut out, format).unwrap(),
        _ => image.write_to(&mut out, format).unwrap(),
    }
    out.into_inner()
}

fn gif(frames: usize, side: u32) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut encoder = GifEncoder::new(&mut out);
        encoder.set_repeat(Repeat::Infinite).unwrap();
        for index in 0..frames {
            let shade = (index * 20 % 255) as u8;
            let frame = RgbaImage::from_pixel(side, side, Rgba([shade, 40, 200, 255]));
            encoder
                .encode_frame(Frame::from_parts(
                    frame,
                    0,
                    0,
                    Delay::from_numer_denom_ms(50, 1),
                ))
                .unwrap();
        }
    }
    out
}

fn webp_dimensions(bytes: &[u8]) -> (u32, u32, bool, u32) {
    let decoder = image_webp::WebPDecoder::new(Cursor::new(bytes)).unwrap();
    let (width, height) = decoder.dimensions();
    (
        width,
        height,
        decoder.is_animated(),
        if decoder.is_animated() {
            decoder.num_frames()
        } else {
            1
        },
    )
}

const CROP: Crop = Crop {
    x: 4,
    y: 2,
    size: 40,
};

#[test]
fn every_type_becomes_two_square_webp_images() {
    for format in [
        ImageFormat::Jpeg,
        ImageFormat::Png,
        ImageFormat::Gif,
        ImageFormat::WebP,
        ImageFormat::Bmp,
        ImageFormat::Tiff,
    ] {
        let data = encoded(format, 64, 48);
        let output = convert(&data, CROP).unwrap_or_else(|why| panic!("{format:?}: {why:?}"));
        assert_eq!(
            webp_dimensions(&output.large),
            (256, 256, false, 1),
            "{format:?}"
        );
        assert_eq!(
            webp_dimensions(&output.small),
            (64, 64, false, 1),
            "{format:?}"
        );
        assert!(!output.animated);
        assert_eq!(&output.large[..4], b"RIFF");
    }
}

#[test]
fn a_gif_keeps_its_animation() {
    let output = convert(
        &gif(4, 48),
        Crop {
            x: 0,
            y: 0,
            size: 48,
        },
    )
    .unwrap();
    assert!(output.animated);
    assert_eq!(webp_dimensions(&output.large), (256, 256, true, 4));
    assert_eq!(webp_dimensions(&output.small), (64, 64, true, 4));
    // One frame is a still picture.
    assert!(
        !convert(
            &gif(1, 48),
            Crop {
                x: 0,
                y: 0,
                size: 48
            }
        )
        .unwrap()
        .animated
    );
}

#[test]
fn the_type_comes_from_the_bytes_not_a_name() {
    let info = inspect(&encoded(ImageFormat::Png, 10, 20)).unwrap();
    assert_eq!(
        (info.format, info.width, info.height, info.frames),
        (Format::Png, 10, 20, 1)
    );
    assert_eq!(
        inspect(b"<svg xmlns='http://www.w3.org/2000/svg'/>"),
        Err(Refusal::Svg)
    );
    assert_eq!(
        inspect(b"\xEF\xBB\xBF \n<?xml version='1.0'?><svg/>"),
        Err(Refusal::Svg)
    );
    assert_eq!(
        inspect(b"MZ\x90\x00 not a picture"),
        Err(Refusal::Unsupported)
    );
    assert_eq!(inspect(b""), Err(Refusal::Unsupported));
}

#[test]
fn heic_is_told_to_convert_and_other_boxes_are_unsupported() {
    let boxed = |major: &[u8; 4], compatible: &[u8; 4]| {
        let mut data = vec![0, 0, 0, 24];
        data.extend_from_slice(b"ftyp");
        data.extend_from_slice(major);
        data.extend_from_slice(&[0, 0, 0, 0]);
        data.extend_from_slice(compatible);
        data.extend_from_slice(b"mif1");
        data
    };
    assert_eq!(inspect(&boxed(b"heic", b"mif1")), Err(Refusal::Heic));
    assert_eq!(inspect(&boxed(b"mif1", b"heix")), Err(Refusal::Heic));
    assert_eq!(inspect(&boxed(b"isom", b"mp41")), Err(Refusal::Unsupported));
    assert_eq!(Refusal::Heic.message(), "Convert it to JPEG or PNG first");
}

#[test]
fn size_pixels_and_frames_are_checked_from_the_header() {
    assert_eq!(inspect(&vec![0xFF; MAX_BYTES + 1]), Err(Refusal::TooLarge));
    assert_eq!(
        inspect(&encoded(ImageFormat::Png, 4097, 1)),
        Err(Refusal::Dimensions)
    );
    assert_eq!(
        inspect(&encoded(ImageFormat::Png, 1, 4097)),
        Err(Refusal::Dimensions)
    );
    assert!(inspect(&encoded(ImageFormat::Png, 4096, 1)).is_ok());
    assert_eq!(inspect(&gif(301, 1)), Err(Refusal::Frames));
    assert_eq!(inspect(&gif(300, 1)).map(|info| info.frames), Ok(300));
    // 120 frames of 1000 x 1000 is more work than the helper may do; 100 is the cap.
    assert_eq!(inspect(&gif(120, 1000)), Err(Refusal::Work));
    assert!(inspect(&gif(100, 1000)).is_ok());
}

#[test]
fn a_crop_must_be_a_square_inside_the_picture() {
    let data = encoded(ImageFormat::Png, 64, 48);
    for crop in [
        Crop {
            x: 0,
            y: 0,
            size: 0,
        },
        Crop {
            x: 30,
            y: 0,
            size: 40,
        },
        Crop {
            x: 0,
            y: 20,
            size: 40,
        },
        Crop {
            x: u32::MAX,
            y: 0,
            size: 2,
        },
    ] {
        assert_eq!(convert(&data, crop).err(), Some(Refusal::Crop), "{crop:?}");
    }
    assert!(
        convert(
            &data,
            Crop {
                x: 0,
                y: 0,
                size: 48
            }
        )
        .is_ok()
    );
}

#[test]
fn damaged_pictures_are_refused_not_crashed_on() {
    let mut data = encoded(ImageFormat::Png, 64, 48);
    data.truncate(data.len() / 2);
    assert_eq!(convert(&data, CROP).err(), Some(Refusal::Decode));
    let mut jpeg = encoded(ImageFormat::Jpeg, 64, 48);
    jpeg.truncate(30);
    assert!(convert(&jpeg, CROP).is_err());
}

#[test]
fn the_wire_round_trips_and_refuses_a_bad_request() {
    let data = encoded(ImageFormat::Png, 64, 48);
    let reply = wire::handle(&wire::request(CROP, &data));
    let output = wire::parse_response(&reply).unwrap().unwrap();
    assert_eq!(webp_dimensions(&output.large), (256, 256, false, 1));
    let refused = wire::handle(&wire::request(
        Crop {
            x: 99,
            y: 0,
            size: 10,
        },
        &data,
    ));
    assert_eq!(wire::parse_response(&refused), Some(Err(Refusal::Crop)));
    let garbage = wire::handle(b"not json\nbytes");
    assert_eq!(wire::parse_response(&garbage), Some(Err(Refusal::Crop)));
    assert_eq!(
        wire::parse_response(
            b"{\"result\":\"ok\",\"large\":5,\"small\":5,\"animated\":false}\nshort"
        ),
        None
    );
    assert_eq!(wire::parse_response(b""), None);
}

#[test]
fn encoders_used_here_exist() {
    // Keeps ImageEncoder in use for the formats above.
    fn assert_encoder<T: ImageEncoder>() {}
    assert_encoder::<image::codecs::png::PngEncoder<Vec<u8>>>();
}

/// A 400 x 300 JPEG, red on the left half and blue on the right, with an EXIF
/// orientation tag of `orientation` (6 = shown turned 90 degrees clockwise).
fn jpeg_with_orientation(orientation: u8) -> Vec<u8> {
    let image = RgbaImage::from_fn(400, 300, |x, _| {
        if x < 200 {
            Rgba([220, 20, 20, 255])
        } else {
            Rgba([20, 20, 220, 255])
        }
    });
    let mut plain = Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image)
        .to_rgb8()
        .write_to(&mut plain, ImageFormat::Jpeg)
        .unwrap();
    let plain = plain.into_inner();
    let mut exif = b"Exif\0\0MM\0\x2A\0\0\0\x08\0\x01\x01\x12\0\x03\0\0\0\x01".to_vec();
    exif.extend_from_slice(&[0, orientation, 0, 0, 0, 0, 0, 0]);
    let mut out = plain[..2].to_vec();
    out.extend_from_slice(&[0xFF, 0xE1]);
    out.extend_from_slice(&((exif.len() + 2) as u16).to_be_bytes());
    out.extend_from_slice(&exif);
    out.extend_from_slice(&plain[2..]);
    out
}

#[test]
fn a_photo_stored_sideways_is_cropped_the_way_the_browser_shows_it() {
    let photo = jpeg_with_orientation(6);
    // The browser shows it 300 wide and 400 tall, so that is the frame of the crop.
    let info = inspect(&photo).unwrap();
    assert_eq!((info.width, info.height), (300, 400));
    // Inside the shown picture, though outside the stored one's height.
    let output = convert(
        &photo,
        Crop {
            x: 0,
            y: 50,
            size: 300,
        },
    )
    .unwrap();
    // Turned 90 degrees clockwise the red left half is the top: rows 50..200 of the
    // crop's 300 are red, the rest blue.
    let decoded = image::load_from_memory_with_format(&output.large, ImageFormat::WebP)
        .unwrap()
        .to_rgba8();
    let (top, bottom) = (decoded.get_pixel(128, 10), decoded.get_pixel(128, 245));
    assert!(top[0] > top[2] + 100, "top should be red: {top:?}");
    assert!(
        bottom[2] > bottom[0] + 100,
        "bottom should be blue: {bottom:?}"
    );
    // A crop in the stored frame (400 wide) no longer fits.
    let stored = Crop {
        x: 0,
        y: 0,
        size: 400,
    };
    assert_eq!(convert(&photo, stored).err(), Some(Refusal::Crop));
    // Not turned, the same file is 400 x 300.
    let upright = inspect(&jpeg_with_orientation(1)).unwrap();
    assert_eq!((upright.width, upright.height), (400, 300));
}
