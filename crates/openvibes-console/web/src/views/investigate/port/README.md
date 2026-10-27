# views/investigate/port

A port's page (approved screen 20; roles spec §10.3, step 5e rulings 18 and 20–25), at `/ports/{port}/{protocol}` (it reads "22/tcp"). It replaces the old port panel: old links (`?open=port:tcp:443`, `nav.open({kind: "port"})`) come here through `app/location.ts`'s `parsePortId`, which reads `tcp/443`, `tcp:443`, `443/tcp` and `443`.

| File | What it does |
|---|---|
| `PortPage.tsx` | The page: header (Add to case with kind `port`, Ask about this, ⋯ Export and Copy link), four tiles, Export's CSV rows, and the 404 page. |
| `PortCards.tsx` | Details, By group and Recent changes on the left; Hosts (segments, the paged table, the 24-hour stale-report warning) and Related (failing checks, vulnerabilities of the usual server's packages, open alarms) on the right. |

More: [docs/components/console-ports.md](../../../../../../../docs/components/console-ports.md)
