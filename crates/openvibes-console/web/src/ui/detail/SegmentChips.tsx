// A row of count chips that picks one segment ("All 12", "Web 3"): Segmented
// (radio group, arrows, Home and End, one tab stop) with a count after each label.
import { Segmented } from "../Segmented";

export function SegmentChips(props: Readonly<{
  label: string;
  options: { key: string; label: string; count: number }[];
  value: string;
  onChange: (key: string) => void;
}>) {
  const options = props.options.map((o) => ({ value: o.key, label: o.label, suffix: o.count.toLocaleString() }));
  return <Segmented label={props.label} value={props.value} onChange={props.onChange} options={options} />;
}
