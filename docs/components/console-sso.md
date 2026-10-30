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
is refused and not created; an existing person left with none is refused and
their identity-provider roles are revoked. A disabled person is refused.
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
