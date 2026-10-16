"""Requires the stack running with SUPERSET_OIDC_SYNC_MODE=merge - see `mise run
test:merge-mode`, which brings the stack up that way, runs this module, and restores
the default "overwrite" config afterward. Not part of the default `mise run test`."""

import pytest
from helpers.ui import grant_role_via_ui, logout_via_direct_link

pytestmark = pytest.mark.merge_mode


def test_merge_mode_manual_role_survives_multiple_successive_syncs(
    page, base_url, login_as, throwaway_user
):
    """A single relogin isn't enough to prove merge mode is stable over time: this chains
    three successive OIDC logins with the token unchanged, to catch a regression where a
    manually-granted role gets silently absorbed into OIDC's tracked-role history (and
    then revoked) a cycle or two after it was first preserved - which a one-shot test
    would miss, since the history is only corrupted on the *second* post-grant login."""
    login_as(throwaway_user, throwaway_user)
    roles = page.request.get(f"{base_url}/api/v1/me/roles/")
    assert set(roles.json()["result"]["roles"].keys()) == {"Gamma"}
    logout_via_direct_link(page, base_url)

    login_as("admin.dev", "admin.dev")
    grant_role_via_ui(page, base_url, throwaway_user, "Alpha")
    logout_via_direct_link(page, base_url)

    for _ in range(3):
        login_as(throwaway_user, throwaway_user)
        roles = page.request.get(f"{base_url}/api/v1/me/roles/")
        assert set(roles.json()["result"]["roles"].keys()) == {"Alpha", "Gamma"}
        logout_via_direct_link(page, base_url)


def test_merge_mode_removes_role_dropped_from_token(
    page, base_url, login_as, throwaway_user, keycloak_admin
):
    """Merge mode isn't a permanent union: a role that *was* OIDC-tracked and then
    disappears from the token must still be revoked, exactly like in "overwrite" mode."""
    user_id = keycloak_admin.get_user_id(throwaway_user)
    keycloak_admin.set_client_roles(user_id, ["Alpha"])
    login_as(throwaway_user, throwaway_user)
    roles = page.request.get(f"{base_url}/api/v1/me/roles/")
    assert set(roles.json()["result"]["roles"].keys()) == {"Alpha", "Gamma"}
    logout_via_direct_link(page, base_url)

    keycloak_admin.set_client_roles(user_id, [])
    login_as(throwaway_user, throwaway_user)
    roles = page.request.get(f"{base_url}/api/v1/me/roles/")
    assert set(roles.json()["result"]["roles"].keys()) == {"Gamma"}


def test_merge_mode_oidc_absorbs_a_previously_manual_role(
    page, base_url, login_as, throwaway_user, keycloak_admin
):
    """A role granted manually is only safe from OIDC resync until the IdP starts
    asserting that same role: once it shows up in a token, that login starts tracking
    it as OIDC-owned, and it is revoked again if the IdP later drops it - same as any
    other OIDC role."""
    user_id = keycloak_admin.get_user_id(throwaway_user)
    login_as(throwaway_user, throwaway_user)
    roles = page.request.get(f"{base_url}/api/v1/me/roles/")
    assert set(roles.json()["result"]["roles"].keys()) == {"Gamma"}
    logout_via_direct_link(page, base_url)

    login_as("admin.dev", "admin.dev")
    grant_role_via_ui(page, base_url, throwaway_user, "Alpha")
    logout_via_direct_link(page, base_url)

    # Keycloak now also asserts Alpha: this login applies it and starts tracking it as
    # OIDC-owned alongside Gamma.
    keycloak_admin.set_client_roles(user_id, ["Alpha"])
    login_as(throwaway_user, throwaway_user)
    roles = page.request.get(f"{base_url}/api/v1/me/roles/")
    assert set(roles.json()["result"]["roles"].keys()) == {"Alpha", "Gamma"}
    logout_via_direct_link(page, base_url)

    # Keycloak drops Alpha again: it is now revoked, unlike a role that had stayed manual.
    keycloak_admin.set_client_roles(user_id, [])
    login_as(throwaway_user, throwaway_user)
    roles = page.request.get(f"{base_url}/api/v1/me/roles/")
    assert set(roles.json()["result"]["roles"].keys()) == {"Gamma"}
