// Step "Permissions": areas as rows, View / Change / Export / Approve and publish
// as columns, each permission a chip. "All" per row, a toggle per column heading.
import { AREAS, CATALOGUE, type PermissionId, labelOf } from "../../../app/permissions";
import { Icon } from "../../../ui/Icon";
import { type Action, COLUMNS, type RoleState } from "./roleState";

export const PLATFORM_TIP = "Applies to the whole platform, whatever hosts the role reaches";

export const InfoMark = () => <span className="info-mark" title={PLATFORM_TIP}><Icon name="info" size={13} /><span className="sr-only">(platform-wide)</span></span>;

export function PermissionMatrix({ state, dispatch, readOnly }: { state: RoleState; dispatch: (action: Action) => void; readOnly: boolean }) {
  const allOn = (ids: readonly PermissionId[]) => ids.length > 0 && ids.every((id) => state.on.has(id));
  return (
    <div className="card role-matrix">
      <table className="table" aria-label="Permissions">
        <thead>
          <tr>
            <th className="role-matrix__area">Area</th>
            {COLUMNS.map((column) => {
              const on = allOn(CATALOGUE.filter((p) => p.column === column).map((p) => p.id));
              return (
                <th key={column}>
                  <span className="row role-matrix__heading">{column}
                    <button type="button" className="role-matrix__toggle" disabled={readOnly} title={`${on ? "Turn off" : "Turn on"} this column in every area`}
                      aria-label={`${on ? "None" : "All"} in ${column}`} onClick={() => dispatch({ type: "column", column })}>{on ? "none" : "all"}</button>
                  </span>
                </th>
              );
            })}
            <th className="role-matrix__all"><span className="sr-only">Whole area</span></th>
          </tr>
        </thead>
        <tbody>
          {AREAS.map((area) => {
            const perms = CATALOGUE.filter((p) => p.area === area);
            const areaPlatform = perms.every((p) => p.scope === "platform");
            const count = perms.filter((p) => state.on.has(p.id)).length;
            return (
              <tr key={area}>
                <td className="role-matrix__area">
                  <div className="role-matrix__label">
                    <span className="row role-matrix__name"><strong>{area}</strong>{areaPlatform && <InfoMark />}</span>
                    <span className="subtle num">{count ? `${count} of ${perms.length} on` : "none"}</span>
                  </div>
                </td>
                {COLUMNS.map((column) => {
                  const cell = perms.filter((p) => p.column === column);
                  return (
                    <td key={column}>
                      <div className="row row--wrap role-matrix__cell">
                        {cell.length === 0 && <span className="role-matrix__empty" aria-hidden="true">·</span>}
                        {cell.map((p) => {
                          const needs = p.needs.length ? ` (needs ${p.needs.map(labelOf).join(", ")})` : "";
                          return (
                            <button key={p.id} type="button" className="chip" aria-pressed={state.on.has(p.id)} aria-label={p.scope === "platform" ? `${p.label} (platform-wide)` : p.label} data-changed={state.changed.get(p.id)}
                              disabled={readOnly} title={`${p.label}${needs}`} onClick={() => dispatch({ type: "toggle", permission: p.id })}>
                              {p.scope === "platform" && !areaPlatform && <InfoMark />}{p.label}
                            </button>
                          );
                        })}
                      </div>
                    </td>
                  );
                })}
                <td className="role-matrix__all">
                  <button type="button" className="button button--ghost button--small" disabled={readOnly} aria-label={`${allOn(perms.map((p) => p.id)) ? "None" : "All"} in ${area}`}
                    onClick={() => dispatch({ type: "area", area })}>{allOn(perms.map((p) => p.id)) ? "None" : "All"}</button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
