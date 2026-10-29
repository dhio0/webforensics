"""Minimal read-only client for the Wazuh indexer (OpenSearch 2.19 REST API).

Standard library only. TLS is always verified: against `ca_file` if given, else the
system store. `server_name` lets the lab connect to 127.0.0.1 while still checking the
certificate's DNS name (wazuh.indexer). Paging uses a point in time (PIT) plus
`search_after`, as the OpenSearch 2.19 pagination docs recommend for deep results; there
are no retries, so a failed page stops the pull instead of silently reordering hits.
"""

import base64
import http.client
import json
import socket
import ssl
from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import quote, urlencode, urlsplit

MAX_ERROR_BODY = 300


class IndexerError(RuntimeError):
    """The indexer refused or failed a request. Never contains credentials."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"indexer returned HTTP {status}: {message}")
        self.status = status


class _Connection(http.client.HTTPSConnection):
    """Connect to `address` but verify the certificate for `server_name`."""

    def __init__(self, address: str, port: int, server_name: str, context: ssl.SSLContext,
                 timeout: float) -> None:
        super().__init__(address, port, timeout=timeout, context=context)
        self._server_name = server_name
        self._ssl_context = context

    def connect(self) -> None:
        raw = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._ssl_context.wrap_socket(raw, server_hostname=self._server_name)


@dataclass(frozen=True)
class Credentials:
    user: str
    password: str


class IndexerClient:
    def __init__(self, url: str, credentials: Credentials, ca_file: str | None = None,
                 server_name: str | None = None, timeout: float = 30.0) -> None:
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError("the indexer URL must be https://host[:port]")
        self._host = parts.hostname
        self._port = parts.port or 9200
        self._server_name = server_name or parts.hostname
        self._context = ssl.create_default_context(cafile=ca_file)
        self._timeout = timeout
        token = f"{credentials.user}:{credentials.password}".encode()
        self._auth = "Basic " + base64.b64encode(token).decode("ascii")

    def request(self, method: str, path: str, body: dict[str, object] | None = None,
                params: dict[str, str] | None = None) -> dict[str, object]:
        target = path + (f"?{urlencode(params)}" if params else "")
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Authorization": self._auth, "Accept": "application/json"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        conn = _Connection(self._host, self._port, self._server_name, self._context,
                           self._timeout)
        try:
            conn.request(method, target, body=payload, headers=headers)
            response = conn.getresponse()
            data = response.read()
        finally:
            conn.close()
        if response.status >= 300:
            text = data.decode("utf-8", "replace")[:MAX_ERROR_BODY]
            raise IndexerError(response.status, text)
        decoded = json.loads(data) if data else {}
        if not isinstance(decoded, dict):
            raise IndexerError(response.status, "response is not a JSON object")
        return decoded

    def has_indices(self, pattern: str) -> bool:
        """True if the pattern matches at least one index the user can read."""
        try:
            self.request("POST", f"/{quote(pattern, safe='*,-')}/_search",
                         {"size": 0, "track_total_hits": False},
                         {"allow_no_indices": "false"})
        except IndexerError as exc:
            if exc.status == 404:
                return False
            raise
        return True

    def iter_hits(self, pattern: str, query: dict[str, object],
                  sort: tuple[dict[str, str], ...], page_size: int = 1000,
                  keep_alive: str = "2m") -> Iterator[dict[str, object]]:
        """All hits of `query` in `sort` order, page by page under one PIT."""
        opened = self.request("POST", f"/{quote(pattern, safe='*,-')}/_search/point_in_time",
                              params={"keep_alive": keep_alive})
        pit_id = str(opened["pit_id"])
        try:
            after: list[object] | None = None
            while True:
                body: dict[str, object] = {
                    "size": page_size, "query": query, "sort": list(sort),
                    "pit": {"id": pit_id, "keep_alive": keep_alive},
                    "track_total_hits": False,
                }
                if after is not None:
                    body["search_after"] = after
                result = self.request("POST", "/_search", body)
                hits = result.get("hits", {}).get("hits", [])  # type: ignore[union-attr]
                if not hits:
                    return
                yield from hits
                after = hits[-1]["sort"]
                if len(hits) < page_size:
                    return
        finally:
            self.request("DELETE", "/_search/point_in_time", {"pit_id": [pit_id]})
