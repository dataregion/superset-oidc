FROM apache/superset:3.1.0

USER root

RUN pip install psycopg[c,pool]

# Dependencies for oidc module
RUN pip install Authlib
RUN pip install flask_openid==1.3.0
RUN pip install flask-oidc==1.3.0
RUN pip install itsdangerous==2.0.1

# Local configuration for the examples
COPY ./superset_config.py /app/pythonpath/superset_config.py
COPY ./client_secret.json /app/pythonpath/client_secret.json
