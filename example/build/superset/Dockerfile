FROM apache/superset:5.0.0

USER root
RUN apt update && apt install -y git

RUN uv pip install --python /app/.venv/bin/python psycopg2-binary psycopg[binary,pool]


# Local configuration for the examples
COPY ./superset_config.py /app/pythonpath/superset_config.py
COPY ./client_secret.json /app/pythonpath/client_secret.json
