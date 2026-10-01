import os
import uuid
from collections.abc import Iterator
from typing import Callable

import pytest
from helpers.keycloak_admin import KeycloakAdmin
from helpers.ui import login_via_ui


@pytest.fixture(scope="session")
def superset_url() -> str:
    return os.environ.get("SUPERSET_URL", "http://localhost:8088").rstrip("/")


@pytest.fixture(scope="session")
def keycloak_url() -> str:
    return os.environ.get("KEYCLOAK_URL", "http://localhost:8080").rstrip("/")


@pytest.fixture(scope="session")
def keycloak_realm() -> str:
    return os.environ.get("KEYCLOAK_REALM", "superset-dev")


@pytest.fixture(scope="session")
def base_url(superset_url: str) -> str:
    # Overrides pytest-playwright's own base_url fixture so page.goto("/login/") etc.
    # resolve against the running Superset instance.
    return superset_url


@pytest.fixture(scope="session")
def keycloak_admin(keycloak_url: str, keycloak_realm: str) -> Iterator[KeycloakAdmin]:
    with KeycloakAdmin(keycloak_url, keycloak_realm) as admin:
        yield admin


@pytest.fixture
def login_as(page, base_url: str) -> Callable[[str, str], None]:
    def _login(username: str, password: str) -> None:
        login_via_ui(page, base_url, username, password)

    return _login


@pytest.fixture
def realm_lifespans(keycloak_admin: KeycloakAdmin) -> Iterator[Callable[..., None]]:
    """Yields a setter for the realm's token/session lifespans, restored on teardown.

    These are realm-wide, so a test using this fixture cannot run concurrently with any
    other test in the suite - and a leaked value would break every subsequent login.
    """
    tracked = ("accessTokenLifespan", "ssoSessionIdleTimeout", "ssoSessionMaxLifespan")
    original = {key: keycloak_admin.get_realm()[key] for key in tracked}
    current = dict(original)

    def _override(**changes: object) -> None:
        current.update(changes)
        keycloak_admin.update_realm(**current)

    try:
        yield _override
    finally:
        keycloak_admin.update_realm(**original)


@pytest.fixture
def throwaway_user(keycloak_admin: KeycloakAdmin) -> Iterator[str]:
    """A fresh Keycloak user with no Superset counterpart yet, deleted on teardown.

    Needed to exercise sm.py's new-account branch: the 4 seeded realm users only hit it
    once, on the very first login against an empty database.
    """
    username = f"e2e-{uuid.uuid4().hex[:12]}"
    user_id = keycloak_admin.create_user(username, username)
    try:
        yield username
    finally:
        keycloak_admin.delete_user(user_id)
