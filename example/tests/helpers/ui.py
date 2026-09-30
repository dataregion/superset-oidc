"""Browser-driven interactions confirmed against a live dev stack while designing this suite:
Keycloak's default theme login form, and Superset's classic Flask-AppBuilder "Edit User"
view (there is no REST API for editing users/roles on this instance)."""

from __future__ import annotations

from playwright.sync_api import Page


def login_via_ui(page: Page, base_url: str, username: str, password: str) -> None:
    page.goto(f"{base_url}/login/")
    page.get_by_label("Username or email").fill(username)
    page.get_by_label("Password", exact=True).fill(password)
    page.get_by_role("button", name="Sign In").click()
    page.wait_for_url(f"{base_url}/**")


def logout_via_direct_link(page: Page, base_url: str) -> None:
    """Front-channel logout via the module's own route (see src/superset_oidc/sm.py).

    Reliable baseline; the actual "Logout" entry lives behind Superset's Settings dropdown,
    an antd hover submenu that renders its items lazily and is easy to break by relayout,
    so this direct navigation is preferred over chasing that menu's markup.
    """
    page.goto(f"{base_url}/oidc-logout/")


def _open_role_editor(page: Page, base_url: str, target_username: str) -> None:
    page.goto(f"{base_url}/users/list/")
    row = page.locator("tr", has_text=target_username)
    row.get_by_role("link", name="Edit").click()
    page.wait_for_url(f"{base_url}/users/edit/*")


def grant_role_via_ui(page: Page, base_url: str, target_username: str, role_name: str) -> None:
    """Adds `role_name` to `target_username`'s roles through the real Edit User form.

    The role field is a select2 multi-select over a native <select name="roles" multiple>.
    Typing into its search box filters a listbox of matching options; Enter selects the
    highlighted (first) match, mirroring how a human would use the widget.
    """
    _open_role_editor(page, base_url, target_username)
    page.get_by_role("searchbox").fill(role_name)
    page.get_by_role("option", name=role_name, exact=True).wait_for()
    page.get_by_role("searchbox").press("Enter")
    page.get_by_role("button", name="Save").click()
    page.wait_for_url(f"{base_url}/users/list/*")


def revoke_role_via_ui(page: Page, base_url: str, target_username: str, role_name: str) -> None:
    """Removes `role_name` from `target_username`'s roles through the real Edit User form."""
    _open_role_editor(page, base_url, target_username)
    chip = page.get_by_role("listitem", name=role_name, exact=True)
    # select2's remove control is the "x" glyph inside the chip; it has no accessible
    # name of its own (the chip's accessible name is the role name alone).
    chip.locator("xpath=.//*[contains(@class,'select2-selection__choice__remove')]").click()
    page.get_by_role("button", name="Save").click()
    page.wait_for_url(f"{base_url}/users/list/*")
