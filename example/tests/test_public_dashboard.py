"""Anonymous ("public") dashboard access, which rides on the `Public` role that
Flask-AppBuilder hands to every unauthenticated visitor.

Why this concerns an OIDC module at all: Superset does not answer a dashboard an
anonymous visitor may not see with a 403, it redirects to the login view - which here
means a full OIDC authorization request to Keycloak. Getting public exposure wrong
therefore does not merely hide a dashboard, it drags the visitor into a login flow.

Both tests need the dev stack's `DASHBOARD_RBAC` flag (see
example/build/superset/superset_config.py) and the permissions
example/build/superset/public_role_permissions.py grants the `Public` role, which only
take effect through `superset init` - run by `mise run dev:up` and `mise run dev:init`.
"""

import uuid
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from helpers.superset_api import SupersetApi
from helpers.ui import KEYCLOAK_LOGIN_URL
from playwright.sync_api import Page, expect

# The stack ships a single database reachable from the Superset container: its own
# metadata one. `ab_role` is a Flask-AppBuilder table, so it is guaranteed to exist with
# rows in it, which keeps this suite free of any example-data import.
METADATA_DB_URI = "postgresql://postgres:passwd@db:5432/superset"
DATASET_SCHEMA = "public"
DATASET_TABLE = "ab_role"
DATASET_COLUMN = "name"
# One of the roles `superset init` creates, hence a value the chart is bound to display.
DATASET_SAMPLE_VALUE = "sql_lab"


@dataclass(frozen=True)
class Dashboard:
    id: int
    title: str
    path: str


@pytest.fixture
def anonymous_page(page: Page) -> Page:
    """The `page` fixture, named for the property these tests rest on: pytest-playwright
    builds it a fresh browser context, so it carries no Superset session."""
    return page


@pytest.fixture
def published_dashboard(admin_api: SupersetApi) -> Iterator[Dashboard]:
    """A published dashboard owned by admin.dev, holding one chart on one dataset.

    The dataset is what makes a refusal observable: regular RBAC grants *any* visitor a
    dashboard that uses no dataset at all (`not dashboard.datasources` in
    `SupersetSecurityManager.raise_for_access`), published or not.
    """
    suffix = uuid.uuid4().hex[:8]
    title = f"e2e-public-dashboard-{suffix}"
    chart_name = f"{title}-chart"

    database_id = admin_api.create_database(f"e2e-metadata-{suffix}", METADATA_DB_URI)
    dataset_id = admin_api.create_dataset(database_id, DATASET_TABLE, DATASET_SCHEMA)
    dashboard_id = admin_api.create_dashboard(title, published=True)
    chart_id = admin_api.create_chart(
        chart_name, dataset_id, DATASET_COLUMN, [dashboard_id]
    )
    admin_api.place_chart_on_dashboard(dashboard_id, chart_id, chart_name)

    try:
        yield Dashboard(dashboard_id, title, f"/superset/dashboard/{dashboard_id}/")
    finally:
        admin_api.delete("chart", chart_id)
        admin_api.delete("dashboard", dashboard_id)
        admin_api.delete("dataset", dataset_id)
        admin_api.delete("database", database_id)


def test_anonymous_access_to_a_published_dashboard_is_denied(
    anonymous_page: Page, base_url: str, published_dashboard: Dashboard
):
    """Publishing alone exposes nothing: with no role attached, the dashboard falls back
    to dataset-based access, and the Public role holds no `datasource_access`."""
    anonymous_page.goto(f"{base_url}{published_dashboard.path}")

    # The refusal is a redirect to /login/, which this module turns into an authorization
    # request - so the visitor ends up on Keycloak rather than on an error page.
    expect(anonymous_page).to_have_url(KEYCLOAK_LOGIN_URL)


def test_anonymous_access_is_granted_once_the_public_role_is_attached(
    anonymous_page: Page,
    base_url: str,
    admin_api: SupersetApi,
    published_dashboard: Dashboard,
):
    """Attaching `Public` to the dashboard's roles is what exposes it, and it scopes the
    exposure: the dataset stays unreachable outside this dashboard."""
    admin_api.set_dashboard_roles(published_dashboard.id, ["Public"])

    anonymous_page.goto(f"{base_url}{published_dashboard.path}")

    expect(anonymous_page).to_have_url(f"{base_url}{published_dashboard.path}")
    expect(anonymous_page.get_by_text(published_dashboard.title).first).to_be_visible()

    # The visitor really is anonymous, rather than carrying a session leaked from another
    # test: Superset only offers the login link when none is attached.
    expect(anonymous_page.get_by_role("link", name="Login")).to_be_visible()

    # The chart's data made it to the screen, so the chart data API answered the
    # anonymous request too. Nothing granted the Public role `datasource_access`: that
    # query is only served because DASHBOARD_RBAC lets a dashboard vouch for the datasets
    # of the charts it holds.
    expect(anonymous_page.get_by_text(DATASET_SAMPLE_VALUE)).to_be_visible()
