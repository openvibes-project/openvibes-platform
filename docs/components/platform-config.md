# platform-config

Bounded, strict TOML loading shared by every platform binary.

## Interface

- `load::<T>(path) -> Result<T, ConfigError>`: reads at most **64 KiB**,
  requires UTF-8, parses TOML into `T`. `T` should derive `Deserialize` with
  `#[serde(deny_unknown_fields)]`, so a misspelt key is an error rather than
  a silent default.
- `require_absolute(&[&Path]) -> Result<(), ConfigError>`: every configured
  path must be absolute.
- `ConfigError` (`Copy`): `Missing`, `TooLarge`, `Invalid`, `RelativePath`.
  Its messages never include file content or paths, so errors are safe to
  log.

## Failure behaviour

| Input | Result |
|---|---|
| file absent | `Missing` |
| more than 64 KiB (read stops after 64 KiB + 1 byte) | `TooLarge` |
| unreadable, not UTF-8, not TOML, unknown or mistyped key | `Invalid` |
| a relative path passed to `require_absolute` | `RelativePath` |

## Test

`cargo test --locked -p platform-config`
