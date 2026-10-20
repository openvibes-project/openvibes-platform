# src/settings

General settings (roles spec §7): the typed list and changing one value. Both endpoints need `settings.manage`.

| File | What it does |
|---|---|
| `mod.rs` | The folder's modules and `routes()`: `GET /v1/settings`, `PATCH /v1/settings/{key}`. |
| `definitions.rs` | Each setting's key, wording, type, range and default, and the check of a new value. |
| `handlers.rs` | The two handlers. |
| `types.rs` | Request and response types. |
