# api

How the console talks to the platform. Everything else in the app loads and changes data through `client.ts`.

| File | What it does |
|---|---|
| `client.ts` | The one API client: cached loads, paging, mutations that refresh the views showing the data, live or demo. |
| `types.ts` | Short names for the wire types that views and panels use. |
| `generated.ts` | Types generated from the console's OpenAPI document; do not edit by hand. |
| `roles.json` | The built-in role table, generated from the platform so role names always match. |
| `permissions.json` | The permission catalogue (area, text, column, scope, needs), generated from the platform. |
| `templates.json` | The role templates and their permissions, generated from the platform. |

More: [docs/components/console-web.md](../../../../../docs/components/console-web.md)
