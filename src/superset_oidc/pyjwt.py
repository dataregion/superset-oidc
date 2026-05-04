from typing import Any
from jwt import PyJWKClient
import logging

logger = logging.getLogger(__name__)

class FilteredPyJWKClient(PyJWKClient):
    """
    A PyJWKClient which ignores keys with unknown algorithms instead of throwing an exception.
    """

    _EXCEPT_ALGORITHMS = ['RSA-OAEP']

    def fetch_data(self) -> Any:
        data = super().fetch_data()
        return {"keys": [key for key in data.get("keys", []) if key.get("alg", None) not in self._EXCEPT_ALGORITHMS]}
