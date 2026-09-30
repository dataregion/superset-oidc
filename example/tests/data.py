from dataclasses import dataclass


@dataclass(frozen=True)
class SeededUser:
    username: str
    expected_roles: frozenset[str]
    is_admin: bool = False

    @property
    def password(self) -> str:
        # The realm seeds every dev user with password == username.
        return self.username


SEEDED_USERS = [
    SeededUser("admin.dev", frozenset({"Admin", "Gamma"}), is_admin=True),
    SeededUser("alpha.dev", frozenset({"Alpha", "sql_lab", "Gamma"})),
    SeededUser("gamma.dev", frozenset({"Gamma"})),
    SeededUser("noroles.dev", frozenset({"Gamma"})),
]
