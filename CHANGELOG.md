# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.2]

### Fixed
- Logout now correctly clears all OIDC session keys (`oidc_auth_token`, `oidc_auth_profile`, `oidc-sid`) from the Flask session. 
Previously, `oidc.logout()` (deprecated stub returning an ignored redirect) and `logout_user()` (Flask-Login, unaware of OIDC keys) left the token data intact, causing `flask_oidc` to treat the user as still authenticated on subsequent requests.

### Changed
- Logout is now exposed at `/oidc-logout/` instead of `/logout/`.
- Logout session-clearing logic is encapsulated in `AuthOIDCView._do_logout()`.

## [1.3.1] - 2026-05-04

### Fixed
- Back-channel logout session tracking now reads `sid` from the ID token instead of the
  userinfo endpoint. The userinfo endpoint does not include session-level claims; the ID
  token is the correct source. Keycloak's legacy `session_state` claim is used as a
  fallback so that back-channel logout works on all Keycloak versions.

## [1.3.0] - 2026-05-04

### Added
- `CUSTOM_AUTH_ROLES_SYNC_MODE=merge` mode: existing superset roles are preserved and OIDC roles are merged in, rather than overwriting all roles.
- `superset_oidc_plugin__userdata` table to persist OIDC-assigned roles across sessions, enabling accurate role diffing on subsequent logins in `merge` mode.
- Dedicated module `oidc_user_data.py` encapsulating the `OIDCUserData` model and its lifecycle (table creation, role persistence, role retrieval).
- `superset-oidc-sync-db-oidc-roles` CLI command (optional `[cli]` extra) to pre-populate `superset_oidc_plugin__userdata` when migrating an existing instance to `merge` mode.

### Changed
- `merge` mode now tracks previously assigned OIDC roles so that roles removed from the OIDC provider are also removed from the superset user, rather than accumulated indefinitely.
- Logout URL is now resolved from the OIDC provider's discovery document (`end_session_endpoint`) instead of being hardcoded to a Keycloak-specific path. The module now works with any standards-compliant OIDC provider.
- The `sid` claim is now optional: if the provider does not include it, login succeeds and a warning is logged. Back-channel logout is silently disabled for sessions without a `sid`.
- CLI `psycopg2` dependency replaced by `psycopg2-binary` only (the two were declared redundantly).

### Fixed
- HTTP response tuple in `sso_logout` was inverted (`400, msg` instead of `msg, 400`), causing back-channel logout errors to return HTTP 200 instead of 400.
- SQLAlchemy 2.0 incompatibility: `session.bind` (removed in 2.0) replaced by `db.engine`; `Table.create(bind=engine)` keyword argument replaced by positional form.
- `None` could be stored as the OIDC session ID in the Flask session when the provider omits the `sid` claim, risking spurious logouts for all anonymous sessions if a back-channel logout arrived with `sid=None`.

## [1.2.2] - 2025-03-26

### Fixed
- Post-login redirect now respects the `next` query parameter, allowing users to be sent back to the page they were trying to access before authenticating.

## [1.2.1] - 2024-09-18

### Fixed
- Guest token sessions are no longer automatically disconnected when the OIDC session check runs.

## [1.2.0] - 2024-09-18

### Changed
- Updated compatibility for Superset v4 (adjusted dependencies and configuration).

## [1.1.0] - 2024-01-25

### Changed
- Repackaged as a proper Python module with `pyproject.toml`, replacing the previous approach of copying files directly into the Superset image.

## [1.0.0] - 2024-01-25

### Added
- Initial release: OIDC authentication for Superset via `flask-oidc` and Keycloak.
- Back-channel (SSO) logout support.
- Configurable default role via `CUSTOM_AUTH_USER_REGISTRATION_ROLE`.

[Unreleased]: https://github.com/dataregion/superset-oidc/compare/1.3.1...HEAD
[1.3.1]: https://github.com/dataregion/superset-oidc/compare/1.3.0...1.3.1
[1.3.0]: https://github.com/dataregion/superset-oidc/compare/1.2.2...1.3.0
[1.2.2]: https://github.com/dataregion/superset-oidc/compare/1.2.1...1.2.2
[1.2.1]: https://github.com/dataregion/superset-oidc/compare/1.2.0...1.2.1
[1.2.0]: https://github.com/dataregion/superset-oidc/compare/1.1.0...1.2.0
[1.1.0]: https://github.com/dataregion/superset-oidc/compare/1.0.0...1.1.0
[1.0.0]: https://github.com/dataregion/superset-oidc/releases/tag/1.0.0
