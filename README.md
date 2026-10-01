# superset-oidc

Module to use oidc as part of superset authentication.

Superset must be configured to use the module. 

A working example is located [here](./example/).

An example of configuration is located to [superset_config.py](./example/build/superset/superset_config.py).

Also, don't forget to include [client_secret.json](./example/build/superset/client_secret.json).

*Only tested with superset 5*

## Configuration keys

| key                                | type                   | description                                 |
| ---------------------------------- | ---------------------- | ------------------------------------------- |
| CUSTOM_AUTH_USER_REGISTRATION_ROLE | `string` (a role name) | Default role attributed to a superset user. |
| CUSTOM_AUTH_ROLES_SYNC_MODE        | `string`               | Role sync mode: `overwrite` (default) or `merge`. |

## Recommended configuration

### Server-side sessions

OIDC tokens (id\_token, access\_token, refresh\_token) stored in the session can easily exceed Flask's default 4096-byte cookie limit, causing the browser to silently drop the cookie and producing an infinite redirect loop on second login.

It is strongly recommended to enable server-side sessions via [`flask-session`](https://flask-session.readthedocs.io/) (already bundled with Superset 5):

```python
# superset_config.py
SESSION_SERVER_SIDE = True
SESSION_TYPE = 'filesystem'
SESSION_FILE_DIR = '/tmp/superset_sessions'
SESSION_USE_SIGNER = True
SESSION_PERMANENT = False
```

Superset instantiates `flask-session` itself when `SESSION_SERVER_SIDE` is set; no `FLASK_APP_MUTATOR` wiring is needed.

## Limitations

Here are the limitation and the impacts on the superset instance.

- Role affectation in superset is obselete with this module. (when `overwrite` mode is enabled on the `CUSTOM_AUTH_ROLES_SYNC_MODE` configuration key)

## How roles are managed

Roles must exist in superset to be assigned (mapping is *case insensitive*) and a default role (`CUSTOM_AUTH_USER_REGISTRATION_ROLE`) is always set.

### `overwrite` mode

When `overwrite` mode is enabled (default), user roles in superset are replaced with synchronized roles. This means that any existing roles assigned to the user in superset will be removed and replaced with the roles synchronized from the OIDC provider.

### `merge` mode

When `merge` mode is enabled, OIDC roles are kept in sync (added and removed) while roles assigned manually in Superset are preserved. This means a user can hold both OIDC-managed roles and manually assigned roles simultaneously, and changes made to OIDC roles (including removals) are reflected on the next login without affecting manually assigned ones.

Note that this mode keep tracks of oidc synchronized roles by using a custom table named `superset_oidc_plugin__userdata`. This allow handling role deletion.

## Switching from `overwrite` to `merge` mode

> Available since version **1.3.0**

If your Superset instance was already running with `overwrite` mode and you want to switch to `merge` mode, the `superset_oidc_plugin__userdata` table must be seeded with the current roles of each user. Without this step, `merge` mode would start from an empty history and could not distinguish manually assigned roles from OIDC-assigned ones — potentially causing unexpected role changes on the next login.

The `superset-oidc-sync-db-oidc-roles` script (included in the `cli` extra) handles this:

```bash
pip install superset-oidc[cli]

# Preview changes without writing to the database
superset-oidc-sync-db-oidc-roles --db-uri postgresql://user:pass@host/superset --dry-run

# Run the migration
superset-oidc-sync-db-oidc-roles --db-uri postgresql://user:pass@host/superset
```

The database URI can also be provided via the `SQLALCHEMY_DATABASE_URI` environment variable.

Once the script has run, update `superset_config.py` to enable merge mode:

```python
CUSTOM_AUTH_ROLES_SYNC_MODE = "merge"
```

> **Note:** this script is intended for advanced users. Run with `--help` for the full list of options.

## Development environment

The [example/](./example/) stack is a self-contained dev environment: Superset 5 plus a
Keycloak preconfigured by realm import, so no click-through setup is needed.

```bash
mise run dev:up
```

`mise tasks` lists every development task: `dev:reset` to start over from empty databases,
`dev:logs:oidc` to follow this module's logs only, `dev:roles` to show the synchronized
roles, `dev:kc-logout` to trigger a back-channel logout. `mise run test` drives the
[end-to-end tests](#end-to-end-tests) against the running stack. Without
[mise](https://mise.jdx.dev/), the equivalent of `dev:up` is:

```bash
cd example
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```

The dev override mounts the working tree and the configuration files, installs the module
in editable mode and runs Superset under
[debugpy](https://github.com/microsoft/debugpy) — attach a debugger to `localhost:5678`.
`mise run dev:restart` picks up both code and configuration changes; no rebuild is needed.

Omit `-f docker-compose.dev.yml` to run against the module version baked into the image
instead of the working tree.

| Service          | URL                                              | Credentials     |
| ---------------- | ------------------------------------------------ | --------------- |
| Superset         | http://localhost:8088                            | see users below |
| Keycloak admin   | http://localhost:8080                            | `admin`:`admin` |

The `superset-dev` realm seeds four users, each with password equal to their username:

| User          | Client roles in Keycloak      | Exercises                                     |
| ------------- | ----------------------------- | --------------------------------------------- |
| `admin.dev`   | `Admin`                       | nominal admin login                           |
| `alpha.dev`   | `Alpha`, `sql_lab`            | multiple roles                                |
| `gamma.dev`   | `Gamma`, `NoSupersetCounterpart` | a role with no Superset counterpart is skipped |
| `noroles.dev` | *(none)*                      | only `CUSTOM_AUTH_USER_REGISTRATION_ROLE` applies |

The Superset container joins Keycloak's network namespace (`network_mode:
"service:keycloak"`). The issuer in the ID token has to be byte-identical to the one
Superset validates against, which means the same URL must work from the browser and from
inside the container — sharing the namespace makes `http://localhost:8080` designate
Keycloak on both sides, with no external DNS and no `/etc/hosts` entry on the host. Both
ports of the pair are therefore published by the `keycloak` service.

Back-channel logout is wired to `http://localhost:8088/sso-logout/`, which reaches
Superset from Keycloak for the same reason. To exercise it, log in and then force the
logout from Keycloak:

```bash
AT=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d grant_type=password -d client_id=admin-cli -d username=admin -d password=admin \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['access_token'])")
KCUSER=$(curl -s -H "Authorization: Bearer $AT" \
  "http://localhost:8080/admin/realms/superset-dev/users?username=alpha.dev" \
  | python3 -c "import json,sys;print(json.load(sys.stdin)[0]['id'])")
curl -X POST -H "Authorization: Bearer $AT" \
  "http://localhost:8080/admin/realms/superset-dev/users/$KCUSER/logout"
```

The next Superset request then terminates the local session — which is what
the `test_backchannel_logout` end-to-end test below asserts.

To start over from empty databases:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml down -v
```

### End-to-end tests

[example/tests/](./example/tests/) is a [pytest](https://pytest.org) +
[Playwright](https://playwright.dev/python/) suite that drives a real browser against the
running dev stack: login, logout (front-channel and Keycloak-initiated back-channel),
role synchronization for all four seeded users (label-level via the API and
permission-level by checking access to an admin-only page), first-login account
provisioning, and role changes across a re-login. It replaces the ad hoc curl-based
checks this stack used to ship with.

```bash
mise run dev:up
mise run test:install  # one-time Playwright browser download
mise run test
```

The suite is idempotent: every test cleans up what it creates (throwaway Keycloak users,
manually-granted roles), so it can be re-run against a long-lived stack without a
`dev:reset`. It reads `SUPERSET_URL`, `KEYCLOAK_URL` and `KEYCLOAK_REALM` from the
environment (already set by `mise.toml`), runs headless Chromium by default, and keeps a
trace + screenshot for any failing test under `example/tests/test-results/` — open a
trace with `uv run --group e2e playwright show-trace <path>`.

If `test:install` can't download Chromium's headless-shell build (blocked CDN, corporate
proxy), and a full Chromium is already available under `~/.cache/ms-playwright/`, pass
`--browser-channel chromium` to `mise run test`/`test:merge-mode` to use that instead.

This suite runs on every push and pull request via
[.github/workflows/e2e.yml](./.github/workflows/e2e.yml), which brings up the same dev
stack in CI, runs `test` then `test:merge-mode`, and uploads Playwright traces for any
failing test as a build artifact.

#### Merge-mode role sync

`CUSTOM_AUTH_ROLES_SYNC_MODE=merge` (see [How roles are managed](#how-roles-are-managed))
isn't exercised by the default stack, which runs in `overwrite` mode. A dedicated task
brings Superset up with merge mode enabled (via `SUPERSET_OIDC_SYNC_MODE`, read by
[superset_config.py](./example/build/superset/superset_config.py) and set by the
[docker-compose.merge-mode.yml](./example/docker-compose.merge-mode.yml) override), runs
the merge-mode test, and restores `superset`/`superset_init`/`superset_db` to the default
`overwrite` config afterward — even if the test fails:

```bash
mise run test:merge-mode
```

### Editing the realm

The realm lives in [realm-superset-dev.json](./example/build/keycloak/realm-superset-dev.json).
It is imported only when the Keycloak database is empty, so changes require a
`down -v`. Changes made through the admin console are *not* written back to the file —
export the realm from the console if you want to keep them.

Two settings there matter to this module:

- the `superset-client-roles` protocol mapper must keep `userinfo.token.claim` enabled:
  the module reads roles from `session['oidc_auth_profile']`, which flask-oidc populates
  from the userinfo endpoint, not from the ID token.
- `accessTokenLifespan` drives how often flask-oidc refreshes the token on its
  `before_request` hook — lower it to reproduce refresh-heavy behaviour.

## Resources

Heavily inspired of this [article](https://blog.devgenius.io/running-superset-with-openidconnect-keycloak-in-docker-9ef1558d1ea3) 
