# platform-password

Console passwords, shared by the console and the rule signer (board #107)
so both check a password exactly the same way.

- `NormalizedPassword::new` (registration: NFC, 15 to 128 code points, a
  small blocklist) and `for_verification` (NFC, bounded at 4,096 raw code
  points); cleared on drop, never `Debug`-printed.
- `hash_password` (Argon2id, 19 MiB, t=2, p=1) and `verify_password`
  (refuses stored parameters above 64 MiB, t=5, p=4; reports
  `needs_rehash` below the floor).
- `dummy_password_phc`: a credential no account has, to verify unknown
  names against, so they cost the same time as a wrong password.
- `canonical_username`: a console username as stored, or `None`.

Tests: the console's `auth` unit tests (`cargo test -p openvibes-console
--lib auth`) cover hashing, verification bounds and normalization through
its re-exports.
