# superset-oidc

Module to use oidc as part of superset authentication.

Superset must be configured to use the module. 

A working example is located [here](./example/).

An example of configuration is located to [superset_config.py](./example/build/superset/superset_config.py).

Also, don't forget to include [client_secret.json](./example/build/superset/client_secret.json).

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
