###################################################################################
# Common configuration
#
SECRET_KEY='20m6KUQaCGOJr/BBtnoUcTCZlUi7kkf/dnOXrBhMKbIMIrVjuBRimCMp'
SQLALCHEMY_DATABASE_URI = "postgresql://postgres:passwd@db:5432/superset"

WTF_CSRF_ENABLED = True
WTF_CSRF_EXEMPT_LIST = [
    "superset.views.core.log",
    "superset.views.core.explore_json",
    "superset.charts.data.api.data",

    # Exclude superset-oidc from CSRF checks. The back-channel logout call comes from
    # the OIDC provider, which has no way to carry a CSRF token.
    # flask-wtf exempts by "<module>.<view function name>", not by endpoint name.
    'superset_oidc.sm.sso_logout',
    'superset_oidc.sm.login',
    'superset_oidc.sm.logout',
]
WTF_CSRF_TIME_LIMIT = 60 * 60 * 24 * 365

MAPBOX_API_KEY = ''

ENABLE_PROXY_FIX = True

###################################################################################
# Public (anonymous) dashboards
#
# The `Public` role Flask-AppBuilder hands to unauthenticated visitors is populated by
# public_role_permissions.py, which `superset init` runs. PUBLIC_ROLE_LIKE is deliberately
# left unset: Superset 5 can only clone an existing role onto `Public`, and the narrowest
# candidate, `Gamma`, grants far more than viewing a dashboard.
#
# What that script grants is view-level only; reaching a dashboard's data still needs
# either `datasource_access` on its datasets - which opens them to every anonymous
# visitor, through any dashboard built on them - or DASHBOARD_RBAC below.
#
# With DASHBOARD_RBAC, attaching a role to a dashboard scopes access to that dashboard:
# its datasets stay unreachable elsewhere (Explore, the chart data API out of context).
# Attaching `Public` is therefore how a single dashboard is exposed anonymously. Inert
# until a dashboard actually carries roles, in which case it supersedes dataset-based
# access for that dashboard.
FEATURE_FLAGS = {
    "DASHBOARD_RBAC": True,
}

###################################################################################
# Server-side sessions
# OIDC tokens (id_token + access_token + refresh_token) easily exceed the 4096-byte
# cookie limit, causing an infinite redirect loop on second login. Storing sessions
# server-side moves the payload off the cookie; only a signed session ID is kept.
#
from cachelib.file import FileSystemCache

SESSION_SERVER_SIDE = True
SESSION_TYPE = 'cachelib'
SESSION_CACHELIB = FileSystemCache(cache_dir='/tmp/superset_sessions')
SESSION_PERMANENT = False

###################################################################################
# Superset OIDC part
# Here is the meat of the configuration
#
import logging
import os

from flask import Flask
from flask_appbuilder.security.manager import AUTH_OID

from superset_oidc.sm import OIDCSecurityManager, oidc_check_loggedin_or_logout
AUTH_TYPE = AUTH_OID
CUSTOM_SECURITY_MANAGER = OIDCSecurityManager
CUSTOM_AUTH_USER_REGISTRATION_ROLE = "Gamma" # Default role assigned to every user on login
# "overwrite" (default) or "merge" to preserve manually assigned roles.
# Driven by SUPERSET_OIDC_SYNC_MODE so the e2e merge-mode test (mise run test:merge-mode)
# can flip it via a docker-compose override without touching this file.
CUSTOM_AUTH_ROLES_SYNC_MODE = os.environ.get("SUPERSET_OIDC_SYNC_MODE", "overwrite")

## flask-oidc configuration, consumed by superset-oidc ##############################
OIDC_CLIENT_SECRETS =  '/app/pythonpath/client_secret.json'
OIDC_INTROSPECTION_AUTH_METHOD = "client_secret_post"
AUTH_USER_REGISTRATION = True

#####################################
# ADDITIONAL_MIDDLEWARE = [AuthMiddleware, ]

def FLASK_APP_MUTATOR(app: Flask):
    # Set after Superset has configured logging, which resets levels set at import time.
    logging.getLogger('superset_oidc').setLevel(logging.DEBUG)

    @app.before_request
    def before_request():
        oidc_check_loggedin_or_logout()
