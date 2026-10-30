# Console single sign-on (SAML 2.0)

People can sign in through an identity provider (Entra ID, Keycloak, Okta and
the like) instead of a password. Settings are in
[console-settings.md](console-settings.md); storage is in
[platform-store.md](platform-store.md) (`console_sso`). Spec:
`planning/saml-sso-spec-2026-10-29.md`.

## What it does

- The login page asks `GET /auth/v1/sso` and, when single sign-on is on and
  complete, shows "Sign in with single sign-on" above the password form.
- `GET /auth/saml/start` makes a request with a random ID, remembers it for
  five minutes (single use, tied to this browser by the cookie
  `__Host-openvibes-saml`, `SameSite=None` because the response arrives in a
  cross-site POST), and redirects to the sign-in address (HTTP-Redirect).
- `POST /auth/saml/acs` (HTTP-POST) takes the response. A response the
  identity provider started on its own is refused.
- The local `admin` account always signs in with its password. Signing out is
  local only.

## Checks (all must pass)

The request must be ours, unused, unexpired and from the same browser. The
response is at most 256 KiB and has no `<!DOCTYPE` or `<!ENTITY`. Signed with
a certificate that is valid now (RSA or ECDSA with SHA-256, 384 or 512; SHA-1
is refused), over the element we read; Issuer is the stored entity ID;
Destination and Recipient are our reply URL; Audience is our entity ID;
`InResponseTo` is our request; NotBefore and NotOnOrAfter hold (two minutes of
skew), bearer confirmation, success status, no encrypted assertion; a NameID
is present; the assertion ID has not been seen. Missing entity ID, sign-in
address or current certificate means no sign-in at all (never "unsigned is
fine").

## Who gets in

The person is linked by issuer and NameID, never by email or username, so
renaming or reusing an email cannot take over an account. Roles come from the
group attribute (`sso.group_attribute`): a group whose name equals a role's
display name (case-insensitive) gives that role, and the roles are set again
at every sign-in (roles added by hand are kept). Someone in no matching group
is refused and not created. An existing person whose groups no longer match
loses their identity-provider roles and can still sign in while they hold a
role granted by hand; with none left they are refused. A disabled person is refused.
New people get the username `sso.` plus 16 hex digits, the display name from
`sso.name_attribute` (fallback email, then NameID) and the email from
`sso.email_attribute` when it looks like an address. Audit: `user.created`,
`rbac.binding.created/revoked` (actor `console-sso`), `auth.login.succeeded`
with method `saml`.

## Refusals

Every failure sends the person to `/login?sso=failed`, the same page, with
one generic sentence. The audit log holds `auth.saml.refused` with a reason
code only (`incomplete`, `other_browser`, `unknown_request`, `sso_off`,
`too_large`, `bad_signature`, `wrong_request`, `wrong_destination`,
`wrong_audience`, `wrong_issuer`, `expired`, `idp_refused`,
`invalid_response`, `replay`, `no_role`, `disabled`, `unavailable`); never the
response itself.

## Build and packages

samael with the `xmlsec` feature links the C libraries xmlsec1 and libxml2:
the build needs `xmlsec1-devel`, `xmlsec1-openssl-devel`, `libxml2-devel`,
`clang` and `pkgconf-pkg-config` (Fedora) or `libxmlsec1-dev`, `libxml2-dev`,
`libclang-dev` and `pkg-config` (Ubuntu CI); the console RPM needs
`xmlsec1-openssl` and the offline kit gets it with the dependency closure.

## How to test

`cargo test -p openvibes-console --test sso_signin_http` (signed responses
made with samael's own identity provider, then broken one way at a time),
`cargo test -p openvibes-console sso` and
`cargo test -p platform-store --test console_sso` (need
`OPENVIBES_TEST_DATABASE_URL`), `npx vitest run src/shell/SignIn.test.tsx`.

## Housekeeping, locks and the off switch

- `openvibes-admin maintenance` (the daily timer) forgets expired sign-in
  requests and remembered assertions, and removes single sign-on people with
  no sign-in for `sso.remove_inactive_days` days (default 90; a person never
  signed in counts from when they were created). A person that cases, alarms
  or triage still point at cannot be deleted: they keep their row but lose
  their identity-provider roles and sessions (the next sign-in sets the
  roles again). Each is audited as `user.removed` (actor `console-sso`,
  `deleted` true or false).
- People page: for someone who signs in this way the name, email and roles
  are locked (409 `managed_by_sso` on `PATCH /api/v1/users/{id}` and the role
  routes; the page hides Edit details, Add role and Remove). Their picture
  and Disable still work.
- Turning it off without the console: `openvibes-admin sso status` prints
  `on`, `off` or `not set up`; `openvibes-admin sso off` sets the stored
  switch off (audited as `settings.changed`; `already off` or `not set up`
  change nothing). The TUI's Maintenance › Console sign-in shows the state
  and has "Turn single sign-on off" (helper verb `sso-off`, asks for the sudo
  password like the password reset).

## Known limits

- `GET /auth/saml/start` needs no sign-in; at most 2,000 sign-ins can wait at
  once (5 minutes each), so someone who can reach the console could keep the
  table full and make single sign-on answer 503. The local `admin` password
  still works. A per-source rate limit is a later hardening.
- Group names match role display names case-insensitively; display names are
  not unique, so two roles named alike would both be granted. A group named
  like the Administrator role gives that role, as the spec says.
- Every `AudienceRestriction` must name our entity ID.
