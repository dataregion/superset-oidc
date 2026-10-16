"""Superset's REST API, driven through a logged-in browser context.

This instance authenticates via OIDC only, so `/api/v1/security/login` cannot mint a
token out of a username/password pair: the API has to ride on the browser session
cookie, which Superset accepts on the endpoints declaring `allow_browser_login`.
"""

from __future__ import annotations

import json
from typing import Any

from playwright.sync_api import APIRequestContext, APIResponse

TABLE_DATASOURCE_TYPE = "table"


class SupersetApiError(AssertionError):
    """Raised with the response body, which carries Superset's own error messages."""


class SupersetApi:
    """The slice of Superset's API the suite provisions dashboards with."""

    def __init__(self, request: APIRequestContext, base_url: str) -> None:
        self._request = request
        self._base_url = base_url.rstrip("/")
        self._csrf_token: str | None = None

    def create_database(self, name: str, sqlalchemy_uri: str) -> int:
        return self._post(
            "/api/v1/database/",
            {"database_name": name, "sqlalchemy_uri": sqlalchemy_uri},
        )["id"]

    def create_dataset(self, database_id: int, table_name: str, schema: str) -> int:
        return self._post(
            "/api/v1/dataset/",
            {"database": database_id, "schema": schema, "table_name": table_name},
        )["id"]

    def create_dashboard(self, title: str, published: bool) -> int:
        return self._post(
            "/api/v1/dashboard/",
            {"dashboard_title": title, "published": published},
        )["id"]

    def create_chart(
        self, name: str, dataset_id: int, column: str, dashboard_ids: list[int]
    ) -> int:
        return self._post(
            "/api/v1/chart/",
            {
                "slice_name": name,
                "datasource_id": dataset_id,
                "datasource_type": TABLE_DATASOURCE_TYPE,
                "viz_type": "table",
                "dashboards": dashboard_ids,
                "params": json.dumps(
                    {
                        "datasource": f"{dataset_id}__{TABLE_DATASOURCE_TYPE}",
                        "viz_type": "table",
                        "query_mode": "raw",
                        "all_columns": [column],
                        "row_limit": 10,
                    }
                ),
            },
        )["id"]

    def place_chart_on_dashboard(
        self, dashboard_id: int, chart_id: int, chart_name: str
    ) -> None:
        """Lays the chart out so the dashboard actually renders it.

        Linking a chart to a dashboard (`dashboards` on chart creation) is what makes the
        dataset count as one of the dashboard's `datasources` for access checks, but it
        leaves the dashboard visually empty: the layout lives in its own `position_json`.
        """
        chart_component = f"CHART-{chart_id}"
        row = f"ROW-{chart_id}"
        self._put(
            f"/api/v1/dashboard/{dashboard_id}",
            {
                "position_json": json.dumps(
                    {
                        "DASHBOARD_VERSION_KEY": "v2",
                        "ROOT_ID": {
                            "type": "ROOT",
                            "id": "ROOT_ID",
                            "children": ["GRID_ID"],
                        },
                        "GRID_ID": {
                            "type": "GRID",
                            "id": "GRID_ID",
                            "children": [row],
                            "parents": ["ROOT_ID"],
                        },
                        row: {
                            "type": "ROW",
                            "id": row,
                            "children": [chart_component],
                            "parents": ["ROOT_ID", "GRID_ID"],
                            "meta": {"background": "BACKGROUND_TRANSPARENT"},
                        },
                        chart_component: {
                            "type": "CHART",
                            "id": chart_component,
                            "children": [],
                            "parents": ["ROOT_ID", "GRID_ID", row],
                            "meta": {
                                "chartId": chart_id,
                                "sliceName": chart_name,
                                "width": 6,
                                "height": 50,
                            },
                        },
                    }
                )
            },
        )

    def set_dashboard_roles(self, dashboard_id: int, role_names: list[str]) -> None:
        self._put(
            f"/api/v1/dashboard/{dashboard_id}",
            {"roles": [self.role_id(name) for name in role_names]},
        )

    def role_id(self, name: str) -> int:
        """Resolves a role name to its id.

        Flask-AppBuilder's own roles API is not registered on this instance, so the only
        way over HTTP is the "related" endpoint backing the role picker of the dashboard
        properties modal.
        """
        roles = self._get("/api/v1/dashboard/related/roles")["result"]
        for role in roles:
            if role["text"] == name:
                return int(role["value"])
        raise SupersetApiError(f"No role named {name!r} among {[r['text'] for r in roles]}")

    def delete(self, resource: str, resource_id: int) -> None:
        self._expect_ok(
            self._request.delete(
                f"{self._base_url}/api/v1/{resource}/{resource_id}",
                headers=self._mutating_headers(),
            )
        )

    def _get(self, path: str) -> dict[str, Any]:
        return self._expect_ok(self._request.get(f"{self._base_url}{path}")).json()

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._expect_ok(
            self._request.post(
                f"{self._base_url}{path}",
                data=payload,
                headers=self._mutating_headers(),
            )
        ).json()

    def _put(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._expect_ok(
            self._request.put(
                f"{self._base_url}{path}",
                data=payload,
                headers=self._mutating_headers(),
            )
        ).json()

    def _mutating_headers(self) -> dict[str, str]:
        token = self._csrf_token
        if token is None:
            token = self._get("/api/v1/security/csrf_token/")["result"]
            self._csrf_token = token
        return {"X-CSRFToken": token}

    @staticmethod
    def _expect_ok(response: APIResponse) -> APIResponse:
        if not response.ok:
            raise SupersetApiError(
                f"{response.request.method} {response.url} -> {response.status}\n"
                f"{response.text()}"
            )
        return response
