import json

import click
from sqlalchemy import Column, ForeignKey, Integer, MetaData, Table, Text, create_engine, select
from sqlalchemy import inspect as sa_inspect

_OIDC_TABLE = 'superset_oidc_plugin__userdata'


def _build_oidc_table(metadata: MetaData) -> Table:
    return Table(
        _OIDC_TABLE, metadata,
        Column('user_id', Integer, ForeignKey('ab_user.id'), primary_key=True),
        Column('oidc_roles_json', Text, nullable=True),
    )


def _fetch_users_with_roles(conn, ab_user, ab_role, ab_user_role) -> dict[int, dict]:
    rows = conn.execute(
        select(ab_user.c.id, ab_user.c.username, ab_role.c.name.label('role_name'))
        .select_from(ab_user)
        .outerjoin(ab_user_role, ab_user_role.c.user_id == ab_user.c.id)
        .outerjoin(ab_role, ab_role.c.id == ab_user_role.c.role_id)
    ).fetchall()

    users: dict[int, dict] = {}
    for user_id, username, role_name in rows:
        if user_id not in users:
            users[user_id] = {'username': username, 'roles': []}
        if role_name:
            users[user_id]['roles'].append(role_name)
    return users


@click.command('superset-oidc-sync-db-oidc-roles')
@click.option(
    '--db-uri', envvar='SQLALCHEMY_DATABASE_URI', required=True,
    help='URI SQLAlchemy de la base Superset. Peut aussi être fourni via $SQLALCHEMY_DATABASE_URI.',
)
@click.option('--dry-run', is_flag=True, help='Affiche ce qui serait fait sans écrire en base.')
@click.option('--yes', '-y', is_flag=True, help='Ignore la confirmation interactive.')
@click.option(
    '--overwrite', is_flag=True,
    help='Met à jour les entrées existantes dans superset_oidc_plugin__userdata.',
)
def migrate(db_uri: str, dry_run: bool, yes: bool, overwrite: bool):
    """Peuple superset_oidc_plugin__userdata à partir des rôles actuels de chaque utilisateur Superset.

    Chaque rôle existant est traité comme un rôle assigné par OIDC. À utiliser lors de la
    migration d'une instance Superset existante vers le mode 'merge' de superset-oidc.

    \b
    AVERTISSEMENT : ce script est destiné aux utilisateurs avancés.
    Une mauvaise utilisation peut corrompre la table de suivi des rôles OIDC et entraîner
    des attributions ou suppressions de rôles inattendues lors des prochaines connexions.
    Utilisez --dry-run pour vérifier l'effet avant toute écriture en base.
    """
    engine = create_engine(db_uri)

    fab_meta = MetaData()
    fab_meta.reflect(bind=engine, only=['ab_user', 'ab_role', 'ab_user_role'])
    ab_user = fab_meta.tables['ab_user']
    ab_role = fab_meta.tables['ab_role']
    ab_user_role = fab_meta.tables['ab_user_role']

    # La table oidc est définie dans le même MetaData que les tables FAB
    # afin que SQLAlchemy puisse résoudre la FK vers ab_user à la création.
    oidc_table = _build_oidc_table(fab_meta)

    insp = sa_inspect(engine)
    table_exists = insp.has_table(_OIDC_TABLE)

    with engine.connect() as conn:
        users = _fetch_users_with_roles(conn, ab_user, ab_role, ab_user_role)

        existing_ids: set[int] = set()
        if table_exists:
            existing_ids = {row[0] for row in conn.execute(select(oidc_table.c.user_id))}

    if not users:
        click.echo("Aucun utilisateur trouvé.")
        return

    if not table_exists:
        click.echo(f"La table {_OIDC_TABLE} sera créée.")

    click.echo(f"\n{len(users)} utilisateur(s) à traiter :\n")
    for user_id, data in users.items():
        if user_id in existing_ids:
            status = "UPDATE" if overwrite else "SKIP  "
        else:
            status = "INSERT"
        click.echo(f"  [{status}] {data['username']:<30} {data['roles']}")

    if dry_run:
        click.echo("\n[dry-run] Aucune modification effectuée.")
        return

    if not yes:
        click.confirm("\nProcéder à la migration ?", abort=True)

    if not table_exists:
        oidc_table.create(engine)
        click.echo(f"Table {_OIDC_TABLE} créée.")

    inserted = updated = skipped = 0
    with engine.begin() as conn:
        for user_id, data in users.items():
            roles_json = json.dumps(data['roles'])
            if user_id in existing_ids:
                if overwrite:
                    conn.execute(
                        oidc_table.update()
                        .where(oidc_table.c.user_id == user_id)
                        .values(oidc_roles_json=roles_json)
                    )
                    updated += 1
                else:
                    skipped += 1
            else:
                conn.execute(
                    oidc_table.insert().values(user_id=user_id, oidc_roles_json=roles_json)
                )
                inserted += 1

    click.echo(f"\nMigration terminée : {inserted} insérés, {updated} mis à jour, {skipped} ignorés.")
