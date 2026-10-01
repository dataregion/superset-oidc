import time

from helpers.ui import logout_via_direct_link


def test_front_channel_logout(page, base_url, login_as):
    login_as("admin.dev", "admin.dev")
    assert page.request.get(f"{base_url}/api/v1/me/").status == 200

    logout_via_direct_link(page, base_url)

    assert page.request.get(f"{base_url}/api/v1/me/").status == 401


def test_backchannel_logout(page, base_url, login_as, keycloak_admin):
    user = "gamma.dev"
    # Clear any stale sessions first: when several sessions of the same user are live,
    # Keycloak notifies only one of them, and the test would watch a session that never
    # receives the logout token.
    keycloak_admin.force_logout(user)

    login_as(user, user)
    assert page.request.get(f"{base_url}/api/v1/me/").status == 200

    keycloak_admin.force_logout(user)

    # The back-channel POST to /sso-logout/ only marks the session for disconnection;
    # the local session is actually dropped on the next incoming request, via the
    # oidc_check_loggedin_or_logout before_request hook - so poll instead of checking once.
    # 30s gives headroom on a slower/shared CI runner, where Keycloak's async delivery
    # of the logout token can take noticeably longer than on a fast local machine.
    deadline = time.monotonic() + 30
    status = None
    while time.monotonic() < deadline:
        status = page.request.get(f"{base_url}/api/v1/me/").status
        if status == 401:
            break
        time.sleep(1)
    assert status == 401
