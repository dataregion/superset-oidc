"""Grants the `Public` role exactly what an anonymous visitor needs to open a dashboard.

Superset 5 can only populate that role by cloning another one (`PUBLIC_ROLE_LIKE`), and
the narrowest one on offer, `Gamma`, is far too wide for the job: it lets anonymous
visitors browse every dashboard, chart and dataset, and it carries `can_userinfo`, whose
Flask-AppBuilder view answers an anonymous request with a 500 (it reads `g.user.id`).

The list below is the built-in `Public` role Superset 6 ships, backported here. Entries
naming a permission this version doesn't define are reported and skipped.

Run after `superset init`, which creates the permissions this grants and would otherwise
overwrite them. The role is reset to exactly this list on every run, so switching the
stack away from a wider `PUBLIC_ROLE_LIKE` takes effect without a database reset.
"""

import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
logger = logging.getLogger("public_role_permissions")

PUBLIC_ROLE_PERMISSIONS = [
    # Core dashboard viewing
    ("can_read", "Dashboard"),
    ("can_read", "Chart"),
    ("can_dashboard", "Superset"),
    ("can_slice", "Superset"),
    ("can_explore_json", "Superset"),
    ("can_dashboard_permalink", "Superset"),
    ("can_read", "DashboardPermalinkRestApi"),
    # Dashboard filter interactions
    ("can_read", "DashboardFilterStateRestApi"),
    ("can_write", "DashboardFilterStateRestApi"),
    # API access for chart rendering
    ("can_time_range", "Api"),
    ("can_query_form_data", "Api"),
    ("can_query", "Api"),
    # CSS and themes for dashboard styling
    ("can_read", "CssTemplate"),
    ("can_read", "Theme"),
    # Embedded dashboard support
    ("can_read", "EmbeddedDashboard"),
    ("can_read", "CurrentUserRestApi"),
    # Datasource metadata for chart rendering
    ("can_get", "Datasource"),
    ("can_external_metadata", "Datasource"),
    # Annotations on charts
    ("can_read", "Annotation"),
    ("can_read", "AnnotationLayerRestApi"),
    # Chart permalinks (for shared chart links)
    ("can_read", "ExplorePermalinkRestApi"),
]


def main() -> int:
    from superset.app import create_app

    with create_app().app_context():
        from superset import security_manager

        role = security_manager.add_role("Public")
        if role is None:
            logger.error("Could not find or create the Public role")
            return 1

        granted, missing = [], []
        for permission_name, view_name in PUBLIC_ROLE_PERMISSIONS:
            pvm = security_manager.find_permission_view_menu(permission_name, view_name)
            if pvm is None:
                missing.append(f"{permission_name} on {view_name}")
            else:
                granted.append(pvm)

        role.permissions = granted
        security_manager.get_session.commit()

        logger.info("Public role granted %d permissions", len(granted))
        if missing:
            logger.info("Not defined in this Superset version, skipped: %s", ", ".join(missing))
    return 0


if __name__ == "__main__":
    sys.exit(main())
