from playwright.sync_api import expect

from helpers.ui import (
    KEYCLOAK_LOGIN_URL,
    USERINFO_PATH,
    expect_session_active,
    expect_session_rejected,
    expect_session_rejected_eventually,
    logout_via_direct_link,
)

# authlib treats an access token as expired a full minute before its stated expiry (its
# default leeway), so a 5s lifespan makes every Superset request attempt a refresh. That
# is what lets the expiry test observe a refresh failure without waiting on any clock.
_EAGER_REFRESH_LIFESPAN = 5


def test_front_channel_logout(page, base_url, login_as):
    login_as("admin.dev", "admin.dev")
    expect_session_active(page, base_url, "admin.dev")

    logout_via_direct_link(page, base_url)

    expect_session_rejected(page, base_url)


def test_backchannel_logout(page, base_url, login_as, keycloak_admin):
    user = "gamma.dev"
    # Clear any stale sessions first: when several sessions of the same user are live,
    # Keycloak notifies only one of them, and the test would watch a session that never
    # receives the logout token.
    keycloak_admin.force_logout(user)

    login_as(user, user)
    expect_session_active(page, base_url, user)

    keycloak_admin.force_logout(user)

    # 30s gives headroom on a slower/shared CI runner, where Keycloak's async delivery of
    # the logout token can take noticeably longer than on a fast local machine.
    expect_session_rejected_eventually(page, base_url)


def test_logout_when_keycloak_session_expired(
    page, base_url, login_as, keycloak_admin, realm_lifespans
):
    """An expired Keycloak session must log the user out as soon as they navigate.

    Covers the refresh-failure path: Keycloak sends no logout token when a session merely
    expires, so the only thing that notices is flask-oidc retrying the refresh.
    """
    user = "noroles.dev"
    # Several live sessions for one user make which one dies non-deterministic.
    keycloak_admin.force_logout(user)
    realm_lifespans(accessTokenLifespan=_EAGER_REFRESH_LIFESPAN)

    login_as(user, user)
    expect_session_active(page, base_url, user)

    # Keycloak weighs ssoSessionMaxLifespan against the session's start time when the
    # refresh arrives, so dropping it below the live session's age expires that session
    # on the spot - no waiting for a real timeout to elapse.
    realm_lifespans(ssoSessionMaxLifespan=1)

    seen: list[tuple[int, str]] = []
    page.on("response", lambda r: seen.append((r.status, r.url)))
    page.goto(f"{base_url}{USERINFO_PATH}")

    # Assert on the redirect that bounced us, not just on being logged out: the
    # reason=expired hop is flask-oidc's check_token_expiry signature, and distinguishes
    # this from a back-channel logout or any other route that also ends at the login page.
    assert any("reason=expired" in url for _, url in seen), seen
    expect(page).to_have_url(KEYCLOAK_LOGIN_URL)
