from flask_appbuilder import Model
from sqlalchemy import Column, Integer, Text, ForeignKey
import json
import logging

logger = logging.getLogger(__name__)


class OIDCUserData(Model):
    """Stores OIDC metadata per user (outside the FAB User model)."""
    __tablename__ = 'superset_oidc_plugin__userdata'
    user_id = Column(Integer, ForeignKey('ab_user.id'), primary_key=True)
    oidc_roles_json = Column(Text, nullable=True)


def ensure_table(engine):
    """Creates the table if it does not already exist."""
    OIDCUserData.__table__.create(engine, checkfirst=True)
    logger.info("Table superset_oidc_plugin__userdata verified/created.")


def get_previous_oidc_role_names(db_session, user_id: int) -> set[str]:
    """Returns OIDC role names persisted from the last login (uppercased)."""
    row = db_session.query(OIDCUserData).filter_by(user_id=user_id).first()
    if row is None:
        return set()
    return {r.upper() for r in json.loads(row.oidc_roles_json or "[]")}


def save_oidc_roles(db_session, user_id: int, roles: list):
    """Persists the current OIDC roles for the given user."""
    roles_json = json.dumps([r.name for r in roles])
    row = db_session.query(OIDCUserData).filter_by(user_id=user_id).first()
    if row is None:
        db_session.add(OIDCUserData(user_id=user_id, oidc_roles_json=roles_json))
    else:
        row.oidc_roles_json = roles_json
    logger.debug(f"OIDC roles saved to database for user_id={user_id}: {roles}")
