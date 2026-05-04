# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `CUSTOM_AUTH_ROLES_SYNC_MODE=merge` mode: existing superset roles are preserved and OIDC roles are merged in, rather than overwriting all roles.
- `superset_oidc_plugin__userdata` table to persist OIDC-assigned roles across sessions, enabling accurate role diffing on subsequent logins in `merge` mode.
- Dedicated module `oidc_user_data.py` encapsulating the `OIDCUserData` model and its lifecycle (table creation, role persistence, role retrieval).

### Changed
- `merge` mode now tracks previously assigned OIDC roles so that roles removed from the OIDC provider are also removed from the superset user, rather than accumulated indefinitely.

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

[Unreleased]: https://github.com/dataregion/superset-oidc/compare/1.2.2...HEAD
[1.2.2]: https://github.com/dataregion/superset-oidc/compare/1.2.1...1.2.2
[1.2.1]: https://github.com/dataregion/superset-oidc/compare/1.2.0...1.2.1
[1.2.0]: https://github.com/dataregion/superset-oidc/compare/1.1.0...1.2.0
[1.1.0]: https://github.com/dataregion/superset-oidc/compare/1.0.0...1.1.0
[1.0.0]: https://github.com/dataregion/superset-oidc/releases/tag/1.0.0
