FROM apache/superset:3.1.0

USER root
RUN apt update && apt install -y git

RUN pip install psycopg[c,pool]

# Dependencies for oidc module
RUN pip install git+https://github.com/dataregion/superset-oidc.git

# Local configuration for the examples
COPY ./superset_config.py /app/pythonpath/superset_config.py
COPY ./client_secret.json /app/pythonpath/client_secret.json
