# views/investigate/software

A package's page (approved screen 24; roles spec §10.3, step 5g rulings 2 and 11–17), at `/software/{name}` (for example `/software/openssl`). It replaces the old package panel: old links (`?open=package:rpm/openssl`, `nav.open({kind: "package"})`) come here through `app/location.ts`.

| File | What it does |
|---|---|
| `SoftwarePage.tsx` | The page: header (Add to case with kind `software`, ⋯ Export and Copy link), four tiles, Export's CSV rows, and the 404 page. |
| `SoftwareCards.tsx` | Details, Versions (bars, vulnerable ones red), Used by, By group and Recent changes on the left; Vulnerabilities and Hosts (segments, the paged table with "Update to x") on the right. |

More: [docs/components/console-software.md](../../../../../../../docs/components/console-software.md)
