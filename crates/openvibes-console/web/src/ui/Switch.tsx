// On/off row: label left, switch right; the whole row is the button (Space/Enter toggle natively).
export function Switch(props: { label: string; checked: boolean; onChange: (checked: boolean) => void; disabled?: boolean }) {
  const { label, checked, onChange, disabled } = props;
  return (
    <button type="button" role="switch" aria-checked={checked} disabled={disabled} className="switch" onClick={() => onChange(!checked)}>
      <span className="switch__label">{label}</span>
      <span className="switch__track" aria-hidden="true"><span className="switch__knob" /></span>
    </button>
  );
}
