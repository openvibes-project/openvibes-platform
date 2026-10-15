// On/off row: label left, switch right; the whole row is the button (Space/Enter toggle natively).
// `bare`: the track only (a table cell), with the label as its accessible name.
// `busy`: a change is on its way: aria-disabled, so it keeps focus, and presses are ignored.
export function Switch(props: { label: string; checked: boolean; onChange: (checked: boolean) => void; disabled?: boolean; bare?: boolean; busy?: boolean }) {
  const { label, checked, onChange, disabled, bare, busy } = props;
  return (
    <button type="button" role="switch" aria-checked={checked} aria-label={bare ? label : undefined} disabled={disabled} aria-disabled={busy || undefined} className="switch"
      style={bare ? { width: "auto" } : undefined} onClick={() => { if (!busy) onChange(!checked); }}>
      {!bare && <span className="switch__label">{label}</span>}
      <span className="switch__track" aria-hidden="true"><span className="switch__knob" /></span>
    </button>
  );
}
