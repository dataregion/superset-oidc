import pytest
from data import SEEDED_USERS
from helpers.ui import expect_session_active, expect_session_rejected


def test_unauthenticated_access_is_rejected(page, base_url):
    expect_session_rejected(page, base_url)


def test_invalid_credentials_are_rejected(page, base_url):
    page.goto(f"{base_url}/login/")
    page.get_by_label("Username or email").fill("nosuchuser.dev")
    page.get_by_label("Password", exact=True).fill("wrong-password")
    page.get_by_role("button", name="Sign In").click()
    page.wait_for_load_state("networkidle")

    # A successful login always ends up back on Superset; a rejected one never leaves Keycloak.
    assert not page.url.startswith(base_url)
    expect_session_rejected(page, base_url)


@pytest.mark.parametrize("user", SEEDED_USERS, ids=lambda u: u.username)
def test_login_and_role_sync(page, base_url, login_as, user):
    login_as(user.username, user.password)

    expect_session_active(page, base_url, user.username)

    # Label-level: proves both the right roles are attached and (for gamma.dev) that a
    # Keycloak role with no Superset counterpart is silently skipped, not errored on.
    roles = page.request.get(f"{base_url}/api/v1/me/roles/")
    assert roles.status == 200
    assert set(roles.json()["result"]["roles"].keys()) == user.expected_roles

    # Permission-level: proves the attached role carries real Superset permissions, not
    # just a label. Flask-AppBuilder denies access to a classic view with a 302 (flash
    # "Access is Denied" + redirect to the index), not a 403 - there is no REST API for
    # roles/users on this instance to assert against instead.
    admin_only = page.request.get(f"{base_url}/roles/list/", max_redirects=0)
    assert admin_only.status == (200 if user.is_admin else 302)
