// The square kept from an uploaded picture (spec §9.2): the pixels of the
// original, so the server crops the file the person chose, not a screenshot.

export type Crop = { x: number; y: number; size: number };

export const MAX_ZOOM = 4;
/** Larger files are refused by the server (413); say so before uploading. */
export const MAX_BYTES = 10 * 1024 * 1024;

const clamp = (value: number, low: number, high: number) => Math.min(Math.max(value, low), high);

/** The square of side `shortest side / zoom` centred on (cx, cy), kept inside the picture. */
export function cropFor(width: number, height: number, zoom: number, cx: number, cy: number): Crop {
  const size = Math.max(1, Math.floor(Math.min(width, height) / clamp(zoom, 1, MAX_ZOOM)));
  return {
    size,
    x: clamp(Math.round(cx - size / 2), 0, width - size),
    y: clamp(Math.round(cy - size / 2), 0, height - size),
  };
}

/** Where the centre goes when the picture is dragged by (dx, dy) preview pixels. */
export function dragCentre(width: number, height: number, crop: Crop, preview: number, dx: number, dy: number): { cx: number; cy: number } {
  const perPixel = crop.size / preview;
  return {
    cx: clamp(crop.x + crop.size / 2 - dx * perPixel, 0, width),
    cy: clamp(crop.y + crop.size / 2 - dy * perPixel, 0, height),
  };
}

/** The query the server takes: `x=..&y=..&size=..`. */
export const cropQuery = (crop: Crop): string => `x=${crop.x}&y=${crop.y}&size=${crop.size}`;
