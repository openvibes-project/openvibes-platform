# views/investigate/case

A case's page (approved screen 32; roles spec §10.3, step 5d rulings 11-15), at `/cases/{id}`, and the new-case form at `/cases/new`. They replace the old `case` panel; old links (`?open=case:ID`, `nav.open({kind: "case"})` from an alarm, Add to case, a vulnerability's Cases, the palette) come here through `pagePath` in `app/location.ts`.

| File | What it does |
|---|---|
| `CasePage.tsx` | The page: header (Edit, Assign ▾, Close case… with its closing-note dialog and what still blocks it, ⋯ Start investigating / Back to open, Export, Copy link and Reopen), four tiles (items, need an outcome, hosts, open for); Export's CSV rows. |
| `CaseCards.tsx` | Details, Hosts in this case (open problems linking to the filtered lists), Who can see it, and Notes and timeline (the note box at the top, newest first). |
| `CaseItems.tsx` | Items, as screen 32's table (Kind, Item, Severity, Host, Outcome, ✕; Kind, Severity and Host hide on narrow cards): a changed Outcome opens a sub-row with the note, the date and Save (Fixed once the evidence is gone, a note for the others, a date for Risk accepted); ✕ confirms Remove in a sub-row; Add item. |
| `NewCasePage.tsx` | The new-case form, and the assignee hooks Assign reuses. |

More: [docs/components/console-cases.md](../../../../../../../docs/components/console-cases.md), [docs/components/console-web.md](../../../../../../../docs/components/console-web.md)
