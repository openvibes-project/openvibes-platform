# `console_cases`

Cases: one investigation each, with items, outcomes and a timeline. The
component page is `docs/components/console-cases.md`; the public API is
re-exported from `mod.rs`, so callers use `platform_store::console_cases::…`.

| File | What it holds |
|---|---|
| `mod.rs` | The public types, limits and refusals, the viewer, and the small checks (ids, titles, notes, severities) |
| `visibility.rs` | Who sees a case and its items (SQL fragments), and reading a case, its items and its timeline as the viewer sees them |
| `list.rs` | `list`, `get`, `assignees`, `for_item`, `active_items` |
| `items.rs` | Checking what an item points at; `create`, `add_item`, `remove_item` |
| `outcomes.rs` | `set_outcome`: an item's outcome |
| `close.rs` | `update`: fields, closing and a manual reopen |
| `reopen.rs` | The lazy reopen checks the console runs before it reads cases |
| `events.rs` | Timeline entries, audit rows and `add_note` |
| `tests.rs` | Unit tests of the checks (the database tests are in `tests/console_cases.rs`) |
