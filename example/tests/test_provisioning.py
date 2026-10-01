from helpers.ui import logout_via_direct_link


def test_first_login_provisions_account(page, base_url, login_as, throwaway_user, keycloak_admin):
    """Exercises sm.py's new-account branch, which the 4 static seeded users only hit
    once, on the very first login against an empty database."""
    user_id = keycloak_admin.get_user_id(throwaway_user)
    keycloak_admin.set_client_roles(user_id, ["Alpha"])

    login_as(throwaway_user, throwaway_user)

    me = page.request.get(f"{base_url}/api/v1/me/")
    assert me.status == 200
    assert me.json()["result"]["username"] == throwaway_user

    roles = page.request.get(f"{base_url}/api/v1/me/roles/")
    assert set(roles.json()["result"]["roles"].keys()) == {"Alpha", "Gamma"}


def test_role_change_on_relogin(page, base_url, login_as, throwaway_user, keycloak_admin):
    """Proves role sync isn't a one-time snapshot: a real logout/re-login cycle (not just
    revisiting /login/ on a live session, whose cached OIDC profile wouldn't reflect a
    role change) must pick up the updated Keycloak roles."""
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
