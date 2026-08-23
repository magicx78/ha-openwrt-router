"""SSL context selection for the Home Assistant side of the integration.

api.py is deliberately free of Home Assistant imports, so the SSL context for
HTTPS connections is picked here and injected into ``OpenWrtAPI``. Building a
fresh ``ssl.SSLContext`` inside the event loop is a blocking call (it loads
the CA bundle from disk); Home Assistant keeps process-wide cached contexts
for exactly this purpose.
"""

from __future__ import annotations

import ssl

from homeassistant.util.ssl import client_context, client_context_no_verify

from .const import PROTOCOL_HTTP, PROTOCOL_HTTPS_INSECURE


def ssl_context_for_protocol(protocol: str) -> ssl.SSLContext | None:
    """Return HA's cached SSL context for the given protocol (None for HTTP)."""
    if protocol == PROTOCOL_HTTP:
        return None
    if protocol == PROTOCOL_HTTPS_INSECURE:
        return client_context_no_verify()
    return client_context()
