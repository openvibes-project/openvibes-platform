# ui/detail

The shared layout of a detail page (approved screens 11 and 17): header, tiles, and a left and a right column of cards. The host page is the first user.

| File | What it does |
|---|---|
| `DetailPage.tsx` | Header (icon, title, status, facts line, actions), an error callout, tiles, left and right columns; empty slots draw nothing; `Card`, one card of a column (the person, group and settings pages use it too). |
| `Tile.tsx` | One number and its label, a link to the full list it counts ("Open alarms: 3"). |

More: [docs/components/console-web.md](../../../../../../docs/components/console-web.md)
