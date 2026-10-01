"""Keycloak admin-API helper, reimplementing `mise run dev:kc-logout` in Python.

Uses a plain password grant against the master realm's admin-cli client (admin/admin,
the dev stack's fixed credentials), re-fetching the token on every call since call
volume here is trivial and admin tokens are short-lived.
"""

from __future__ import annotations

import httpx


class KeycloakAdmin:
    def __init__(self, base_url: str, realm: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._realm = realm
        self._client = httpx.Client(timeout=10.0)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> KeycloakAdmin:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _headers(self) -> dict[str, str]:
        resp = self._client.post(
            f"{self._base_url}/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": "admin",
                "password": "admin",
            },
        )
        resp.raise_for_status()
        return {"Authorization": f"Bearer {resp.json()['access_token']}"}

    def get_user_id(self, username: str) -> str | None:
        resp = self._client.get(
            f"{self._base_url}/admin/realms/{self._realm}/users",
            params={"username": username, "exact": "true"},
            headers=self._headers(),
        )
        resp.raise_for_status()
        users = resp.json()
        return users[0]["id"] if users else None

    def force_logout(self, username: str) -> None:
        """Ends every active Keycloak SSO session for this user (back-channel logout trigger)."""
        user_id = self.get_user_id(username)
        if user_id is None:
            return
        resp = self._client.post(
            f"{self._base_url}/admin/realms/{self._realm}/users/{user_id}/logout",
            headers=self._headers(),
        )
        resp.raise_for_status()

    def create_user(
        self, username: str, password: str, client_roles: list[str] | None = None
    ) -> str:
        headers = self._headers()
        resp = self._client.post(
            f"{self._base_url}/admin/realms/{self._realm}/users",
            headers=headers,
            json={
                "username": username,
                "enabled": True,
                "emailVerified": True,
                "email": f"{username}@example.org",
                "firstName": "E2E",
                "lastName": "Throwaway",
                "credentials": [
                    {"type": "password", "value": password, "temporary": False}
                ],
            },
        )
        resp.raise_for_status()
        user_id = self.get_user_id(username)
        if user_id is None:
            raise RuntimeError(f"Keycloak did not create user {username!r}")
        if client_roles:
            self.set_client_roles(user_id, client_roles)
        return user_id

    def delete_user(self, user_id: str) -> None:
        resp = self._client.delete(
            f"{self._base_url}/admin/realms/{self._realm}/users/{user_id}",
            headers=self._headers(),
        )
        resp.raise_for_status()

    def _superset_client_uuid(self, headers: dict[str, str]) -> str:
        resp = self._client.get(
            f"{self._base_url}/admin/realms/{self._realm}/clients",
            params={"clientId": "superset"},
            headers=headers,
        )
        resp.raise_for_status()
        clients = resp.json()
        if not clients:
            raise RuntimeError("Keycloak client 'superset' not found")
        return clients[0]["id"]

    def set_client_roles(self, user_id: str, role_names: list[str]) -> None:
        """Replaces this user's `superset` client-role mappings with exactly `role_names`."""
        headers = self._headers()
        client_uuid = self._superset_client_uuid(headers)
        mappings_url = (
            f"{self._base_url}/admin/realms/{self._realm}/users/{user_id}"
            f"/role-mappings/clients/{client_uuid}"
        )

        resp = self._client.get(
            f"{self._base_url}/admin/realms/{self._realm}/clients/{client_uuid}/roles",
            headers=headers,
        )
        resp.raise_for_status()
        available = {role["name"]: role for role in resp.json()}

        resp = self._client.get(mappings_url, headers=headers)
        resp.raise_for_status()
        current = resp.json()
        if current:
            resp = self._client.request(
                "DELETE", mappings_url, headers=headers, json=current
            )
            resp.raise_for_status()

        wanted = [available[name] for name in role_names]
        if wanted:
            resp = self._client.post(mappings_url, headers=headers, json=wanted)
            resp.raise_for_status()
