// Public, non-hashed frontend files emitted by Vite's `public` directory.

/// Exact URL-to-embedded-file mappings for non-hashed public assets.
///
/// Every other embedded file is either the private SPA entry document or a
/// content-hashed file addressed through `/assets/*`.
pub(crate) const PUBLIC_ASSETS: &[(&str, &str)] = &[
    ("/app.webmanifest", "app.webmanifest"),
    ("/theme-bootstrap.js", "theme-bootstrap.js"),
    (
        "/brand/openvibes-mark-placeholder.svg",
        "brand/openvibes-mark-placeholder.svg",
    ),
];
