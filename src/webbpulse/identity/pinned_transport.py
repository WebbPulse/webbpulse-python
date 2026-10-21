"""An `httpx` transport that connects only to the addresses a URL guard approved.

Checking a host's addresses and then letting the HTTP client resolve it again leaves a gap a
rebinding DNS server can use: public on the check, private on the connect. This transport
asks the guard for the approved addresses on every request, redirects included, and sends
the request to one of those literal addresses, so nothing resolves the name a second time.
The `Host` header and TLS server name stay the original host, so the certificate is still
verified against it. Imported only when a pinned client is built, so it needs `httpx` then.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Sequence

import httpx

__all__ = ["PinnedAddressTransport"]

type AddressVetter = Callable[[str], Sequence[str]]
type HostTransportFactory = Callable[[str], httpx.BaseTransport]


def _default_transport(host: str) -> httpx.BaseTransport:
    """A plain verified HTTPS transport, one pool per host."""
    return httpx.HTTPTransport(verify=True, retries=0)


class PinnedAddressTransport(httpx.BaseTransport):
    """Send each request to an address `vet` approved for its URL, never to a fresh lookup.

    `vet(url)` raises to refuse the URL, returns the approved IP addresses, or returns none
    for a host the guard trusts outright, which is then reached normally. Each host gets its
    own connection pool from `transport_for_host`, so a connection verified for one name is
    never reused for another that shares its address.
    """

    def __init__(self, vet: AddressVetter, *, transport_for_host: HostTransportFactory | None = None) -> None:
        """Hold the vetting function and the factory for each host's underlying transport."""
        self._vet = vet
        self._factory: HostTransportFactory = transport_for_host or _default_transport
        self._transports: dict[str, httpx.BaseTransport] = {}
        self._lock = threading.Lock()

    def _transport(self, host: str) -> httpx.BaseTransport:
        """The underlying transport for a host, built on first use."""
        with self._lock:
            transport = self._transports.get(host)
            if transport is None:
                transport = self._factory(host)
                self._transports[host] = transport
            return transport

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Vet the URL, then try each approved address in turn until one connects."""
        addresses = list(self._vet(str(request.url)))
        host = request.url.raw_host.decode("ascii")
        transport = self._transport(host)
        if not addresses:
            return transport.handle_request(request)
        failure: httpx.ConnectError | None = None
        for address in addresses:
            pinned = httpx.Request(
                request.method,
                request.url.copy_with(host=address),
                headers=request.headers,
                stream=request.stream,
                extensions={**request.extensions, "sni_hostname": host},
            )
            try:
                return transport.handle_request(pinned)
            except httpx.ConnectError as exc:
                failure = exc
        raise failure if failure is not None else httpx.ConnectError("No approved address.", request=request)

    def close(self) -> None:
        """Close every host's underlying transport."""
        with self._lock:
            transports = list(self._transports.values())
            self._transports.clear()
        for transport in transports:
            transport.close()
