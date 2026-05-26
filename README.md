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
from flask_session import Session

SESSION_TYPE = 'filesystem'
SESSION_FILE_DIR = '/tmp/superset_sessions'
SESSION_USE_SIGNER = True
SESSION_PERMANENT = False

def FLASK_APP_MUTATOR(app):
    import os
    os.makedirs(app.config.get('SESSION_FILE_DIR', '/tmp/superset_sessions'), exist_ok=True)
    Session(app)
```

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

## Running example

- With docker, run the [docker-compose.yml](./example/docker-compose.yml)

```bash
cd example
docker compose up -d --build --force-recreate
```

- go to [http://localhost:8080](http://localhost:8080) and connect as `admin`:`admin`
  - Create client `superset` on realm `master`
  - Toggle client authentication
    - root url and home url: `http://localhost:8088`
    - fill as depicted here
      ![configuration client superset](./example/configuration_client_superset.png)
    - Go to clients > superset > credentials > copy the client secret and paste it in [client_secret.json](./example/build/superset/client_secret.json) on field `client_secret`
    - restart superset `docker compose up -d --build --force-recreate superset`
    - Create a user. Don't forget to fill in first name and last name.
    - Add credentials to the user.

Now, you can visit [http://localhost:8088](http://localhost:8088) and authenticate with previously setup user.


## Resources

Heavily inspired of this [article](https://blog.devgenius.io/running-superset-with-openidconnect-keycloak-in-docker-9ef1558d1ea3) 
