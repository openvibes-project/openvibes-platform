# views/investigate/service

A service's page (approved screen 22; roles spec §10.3, step 5f rulings 2 and 11–16), at `/services/{unit}` (for example `/services/sshd.service`). It replaces the old unit panel: old links (`?open=unit:sshd.service`, `nav.open({kind: "unit"})`) come here through `app/location.ts`.

| File | What it does |
|---|---|
| `ServicePage.tsx` | The page: header (Add to case with kind `service`, ⋯ Export and Copy link), up to four tiles, Export's CSV rows, and the 404 page. |
| `ServiceCards.tsx` | Details, Ports and By group and Recent changes on the left; Hosts (segments, the paged table, the 24-hour stale-report warning) and Related (failing checks, vulnerabilities of the matched packages, open alarms) on the right. |

More: [docs/components/console-services.md](../../../../../../../docs/components/console-services.md)
