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
# Server-side sessions
# OIDC tokens (id_token + access_token + refresh_token) easily exceed the 4096-byte
# cookie limit, causing an infinite redirect loop on second login. Storing sessions
# server-side moves the payload off the cookie; only a signed session ID is kept.
#
SESSION_SERVER_SIDE = True
SESSION_TYPE = 'filesystem'
SESSION_FILE_DIR = '/tmp/superset_sessions'
SESSION_USE_SIGNER = True
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
OIDC_ID_TOKEN_COOKIE_SECURE = False
OIDC_OPENID_REALM = "superset-dev"
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
