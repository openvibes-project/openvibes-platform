import { useResource } from "../api/client";
import type { MetricHistory } from "../api/types";

/** Daily values of a catalogue metric, oldest first; days with no data are absent. */
export function useHistory(metric: string | null, days: number) {
  const r = useResource<MetricHistory>(metric === null ? null : `/api/v1/metrics/history?metric=${encodeURIComponent(metric)}&days=${days}`);
  return { data: r.data?.points, error: r.error, loading: r.loading };
}
