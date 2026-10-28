// "Change picture" (approved screen 7c): choose a file, move and zoom a
// round preview to pick the square, save. The server converts it (the file
// is never kept) and the 64 px and 256 px images replace the initials.
import { useEffect, useRef, useState } from "react";

import { request, upload } from "../../../api/client";
import { useSession } from "../../../app/session";
import { removeDemoPicture } from "../../../ui/avatar";
import { toast } from "../../../ui/toast";
import { DialogHead, Modal } from "./NewPersonDialog";
import { cropFor, cropQuery, dragCentre, MAX_BYTES, MAX_ZOOM } from "./picture";
import { refreshPeople, refusal, userPath } from "./people";

const PREVIEW = 240;
const ACCEPT = "image/jpeg,image/png,image/gif,image/webp,image/bmp,image/tiff,.jpg,.jpeg,.png,.gif,.webp,.bmp,.tif,.tiff";

type Chosen = { file: File; url: string; width: number; height: number };

export function PictureDialog({ userId, name, hasPicture, onClose }: Readonly<{ userId: string; name: string; hasPicture: boolean; onClose: () => void }>) {
  const { session, reloadSession } = useSession();
  const [chosen, setChosen] = useState<Chosen>();
  const [zoom, setZoom] = useState(1);
  const [centre, setCentre] = useState({ cx: 0, cy: 0 });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const drag = useRef<{ x: number; y: number } | null>(null);
  const file = useRef<HTMLInputElement>(null);
  useEffect(() => () => { if (chosen) URL.revokeObjectURL(chosen.url); }, [chosen]);

  const choose = (picked: File | undefined) => {
    if (!picked) return;
    setError(undefined);
    if (picked.size > MAX_BYTES) { setError("Use a picture of at most 10 MB"); return; }
    const url = URL.createObjectURL(picked);
    const probe = new Image();
    probe.onload = () => {
      setZoom(1);
      setCentre({ cx: probe.naturalWidth / 2, cy: probe.naturalHeight / 2 });
      setChosen({ file: picked, url, width: probe.naturalWidth, height: probe.naturalHeight });
    };
    probe.onerror = () => { URL.revokeObjectURL(url); setError("Your browser cannot show that file. Use a JPEG, PNG, GIF or WebP picture."); };
    probe.src = url;
  };

  const crop = chosen ? cropFor(chosen.width, chosen.height, zoom, centre.cx, centre.cy) : undefined;
  const scale = crop ? PREVIEW / crop.size : 1;
  const move = (dx: number, dy: number) => {
    if (chosen && crop) setCentre(dragCentre(chosen.width, chosen.height, crop, PREVIEW, dx, dy));
  };

  const done = (message: string) => {
    refreshPeople();
    if (session?.principal.id === userId) reloadSession?.();
    toast(message);
    onClose();
  };
  const save = () => {
    if (!chosen || !crop) return;
    setBusy(true);
    setError(undefined);
    upload<{ picture: string }>(`${userPath(userId)}/picture?${cropQuery(crop)}`, chosen.file)
      .then(() => done("Picture saved"), (e: unknown) => setError(refusal(e, "The picture could not be saved.")))
      .finally(() => setBusy(false));
  };
  const remove = () => {
    setBusy(true);
    setError(undefined);
    request("DELETE", `${userPath(userId)}/picture`)
      .then(() => { removeDemoPicture(userId); done("Picture removed"); }, (e: unknown) => setError(refusal(e, "The picture could not be removed.")))
      .finally(() => setBusy(false));
  };

  return (
    <Modal label="Change picture" onClose={onClose}>
      <div className="bulk-dialog stack picture-dialog">
        <DialogHead title={`Picture for ${name}`} onClose={onClose} />
        <p className="subtle">Choose a JPEG, PNG, GIF, WebP, BMP or TIFF picture of at most 10 MB. A GIF stays animated. The file itself is not kept: only the round picture is.</p>
        {chosen && crop ? (
          <div className="stack picture-dialog__crop">
            <button type="button" className="picture-crop" style={{ width: PREVIEW, height: PREVIEW }}
              aria-label="Picture position. Drag, or use the arrow keys."
              onPointerDown={(e) => { drag.current = { x: e.clientX, y: e.clientY }; e.currentTarget.setPointerCapture(e.pointerId); }}
              onPointerMove={(e) => {
                if (!drag.current) return;
                move(e.clientX - drag.current.x, e.clientY - drag.current.y);
                drag.current = { x: e.clientX, y: e.clientY };
              }}
              onPointerUp={() => { drag.current = null; }}
              onPointerCancel={() => { drag.current = null; }}
              onKeyDown={(e) => {
                const step = 12;
                const by: Record<string, [number, number]> = { ArrowLeft: [step, 0], ArrowRight: [-step, 0], ArrowUp: [0, step], ArrowDown: [0, -step] };
                const delta = by[e.key];
                if (delta) { e.preventDefault(); move(delta[0], delta[1]); }
              }}>
              <img alt="" draggable={false} src={chosen.url}
                style={{ width: chosen.width * scale, height: chosen.height * scale, left: -crop.x * scale, top: -crop.y * scale }} />
            </button>
            <label className="field picture-dialog__zoom">
              <span>Zoom</span>
              <input type="range" min={1} max={MAX_ZOOM} step={0.05} value={zoom} onChange={(e) => setZoom(Number(e.target.value))} />
            </label>
          </div>
        ) : null}
        <input ref={file} type="file" className="picture-dialog__file" accept={ACCEPT} aria-label="Picture file" onChange={(e) => { choose(e.target.files?.[0]); e.target.value = ""; }} />
        {error && <p className="confirm__error" role="alert">{error}</p>}
        <div className="row row--between">
          <div className="row">
            <button type="button" className="button" onClick={() => file.current?.click()} disabled={busy}>{chosen ? "Choose another…" : "Choose a file…"}</button>
            {hasPicture && <button type="button" className="button button--ghost" onClick={remove} disabled={busy}>Remove picture</button>}
          </div>
          <div className="row">
            <button type="button" className="button button--ghost" onClick={onClose}>Cancel</button>
            <button type="button" className="button button--primary" disabled={!chosen || busy} onClick={save}>{busy ? "Saving…" : "Save picture"}</button>
          </div>
        </div>
      </div>
    </Modal>
  );
}
