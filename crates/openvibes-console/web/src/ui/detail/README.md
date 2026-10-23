# ui/detail

The shared layout of a detail page (approved screens 11 and 17): header, tiles, and a left and a right column of cards. The host page (`views/investigate/host/`) is the first user.

| File | What it does |
|---|---|
| `DetailPage.tsx` | Header (icon, title, status, facts line, actions), a banner (a due date), an error callout, tiles, left and right columns; empty slots draw nothing; `Card`, one card of a column (the person, group and settings pages use it too). |
| `Tile.tsx` | One number and its label, a link to the full list it counts ("Open alarms: 3"). |
| `FactTile.tsx` | A tile that states a fact ("First seen", "Confidence"): label and value, no link. |
| `SegmentChips.tsx` | A radio group of chips with a count after each label (arrows, Home and End); the Hosts card of the vulnerability page uses it. |
| `RelatedCard.tsx` | The "Related" card: labelled sections, a value is a link when it has an `href`; no sections, no card. |

More: [docs/components/console-web.md](../../../../../../docs/components/console-web.md)
