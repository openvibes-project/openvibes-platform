import { Icon } from "../ui/Icon";

export function Unavailable() {
  return <div className="tile-empty"><Icon name="ban" size={18} /> Not available with your role</div>;
}

/** What a tile shows for a failed count: a 403 is a role matter, anything else the error. */
export function CountError({ error }: { error: { status?: number; message: string } }) {
  return error.status === 403 ? <Unavailable /> : <div className="tile-empty"><Icon name="alert" size={18} /> {error.message}</div>;
}
