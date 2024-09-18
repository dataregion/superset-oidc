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

    'custom.sm.sso_logout', # Exclude superset oidc from csrf checks
    'custom.sm.login',
    'custom.sm.logout',
]
WTF_CSRF_TIME_LIMIT = 60 * 60 * 24 * 365

MAPBOX_API_KEY = ''

ENABLE_PROXY_FIX = True

###################################################################################
# Superset OIDC part
# Here is the meat of the configuration
#
from flask import Flask
from flask_appbuilder.security.manager import AUTH_OID

from superset_oidc.sm import OIDCSecurityManager, oidc_check_loggedin_or_logout
AUTH_TYPE = AUTH_OID
CUSTOM_SECURITY_MANAGER = OIDCSecurityManager
CUSTOM_AUTH_USER_REGISTRATION_ROLE = "Public" # Role de base par défaut synchronisé lors du login

## Configuration du module flask-oidc. part of superset oidc ########################
OIDC_CLIENT_SECRETS =  '/app/pythonpath/client_secret.json'
OIDC_ID_TOKEN_COOKIE_SECURE = False
OIDC_OPENID_REALM: "master"
OIDC_INTROSPECTION_AUTH_METHOD: "client_secret_post"
AUTH_USER_REGISTRATION = True

#####################################
# ADDITIONAL_MIDDLEWARE = [AuthMiddleware, ]

def FLASK_APP_MUTATOR(app: Flask):
    @app.before_request
    def before_request():
        oidc_check_loggedin_or_logout()
