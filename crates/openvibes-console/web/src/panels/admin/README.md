# panels/admin

The admin panels opened from Settings and the audit log. Each is registered as a panel kind in app/registry.tsx.

| File | What it does |
|---|---|
| `ServiceAccountPanel.tsx` | A service account, creating one, and issuing its tokens. |
| `AssetGroupPanel.tsx` | A host group, read-only: its membership sentence and the roles reaching it. |
| `EnrollmentTokenPanel.tsx` | An enrollment token, and creating a new one. |
| `tokens.ts` | Enrollment token state shared by the list and the panel. |
| `AuditPanels.tsx` | An audit event, and the audit retention policy. |

More: [docs/components/console-rbac.md](../../../../../../docs/components/console-rbac.md)
