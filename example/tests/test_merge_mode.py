"""Requires the stack running with SUPERSET_OIDC_SYNC_MODE=merge - see `mise run
test:merge-mode`, which brings the stack up that way, runs this module, and restores
the default "overwrite" config afterward. Not part of the default `mise run test`."""

import pytest
from helpers.ui import grant_role_via_ui, logout_via_direct_link, revoke_role_via_ui

pytestmark = pytest.mark.merge_mode


def test_merge_mode_preserves_manually_assigned_roles(page, base_url, login_as):
    # First login establishes noroles.dev's OIDC-tracked role history: {Gamma}.
    login_as("noroles.dev", "noroles.dev")
    roles = page.request.get(f"{base_url}/api/v1/me/roles/")
    assert set(roles.json()["result"]["roles"].keys()) == {"Gamma"}
    logout_via_direct_link(page, base_url)

    # Admin manually grants Alpha through the real Superset "Edit User" UI - not via OIDC.
    login_as("admin.dev", "admin.dev")
    grant_role_via_ui(page, base_url, "noroles.dev", "Alpha")
    logout_via_direct_link(page, base_url)

    try:
        # Second OIDC login: Alpha must be preserved (it wasn't OIDC-tracked at the
        # previous login), Gamma re-synced. Under "overwrite" this would collapse back
        # to {Gamma} alone - this is the assertion that actually differentiates the modes.
        login_as("noroles.dev", "noroles.dev")
        roles = page.request.get(f"{base_url}/api/v1/me/roles/")
        assert set(roles.json()["result"]["roles"].keys()) == {"Gamma", "Alpha"}
    finally:
        # Don't leak the manual grant into subsequent "overwrite"-mode runs.
        logout_via_direct_link(page, base_url)
        login_as("admin.dev", "admin.dev")
        revoke_role_via_ui(page, base_url, "noroles.dev", "Alpha")
