"""Cautious protocol visibility (task §9; Phase E).

Classifies a flow by transport protocol and port only. Every result is
**heuristic** with an accuracy of ``medium`` at best:

* a port number does not prove which application made the traffic (any
  program may use port 443, a DNS server may run on 5353);
* TLS-encrypted traffic (443, 853, 8883, ...) is never assigned to an
  application: the label names the transport (``https_tls``), the result
  carries ``tls_not_attributed_to_an_application``;
* no deep packet inspection, no TLS decryption, no SNI and no DNS lookup is
  used or needed.

The well-known side is taken from the destination port first (the flow's
initiator talks to a server port), else from the source port (a reply). Two
ephemeral ports give ``unknown`` with accuracy ``none``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Final

from .traffic_const import (
    ACCURACY_LOW,
    ACCURACY_MEDIUM,
    ACCURACY_NONE,
    NOTE_PORT_IS_NO_PROOF,
    NOTE_TLS_NOT_ATTRIBUTED,
    PROTO_BASIS_IP,
    PROTO_BASIS_NONE,
    PROTO_BASIS_PORT,
    PROTO_UNKNOWN,
)

_LOGGER = logging.getLogger(__name__)

# (transport, port) -> (label, accuracy, tls)
KNOWN_PORTS: Final[dict[tuple[str, int], tuple[str, str, bool]]] = {
    ("udp", 53): ("dns", ACCURACY_MEDIUM, False),
    ("tcp", 53): ("dns", ACCURACY_MEDIUM, False),
    ("tcp", 853): ("dns_over_tls", ACCURACY_LOW, True),
    ("udp", 123): ("ntp", ACCURACY_MEDIUM, False),
    ("tcp", 80): ("http", ACCURACY_LOW, False),
    ("tcp", 8080): ("http_alt", ACCURACY_LOW, False),
    ("tcp", 443): ("https_tls", ACCURACY_LOW, True),
    ("udp", 443): ("quic_or_udp_443", ACCURACY_LOW, True),
    ("tcp", 1883): ("mqtt", ACCURACY_MEDIUM, False),
    ("tcp", 8883): ("mqtt_tls", ACCURACY_LOW, True),
    ("tcp", 22): ("ssh", ACCURACY_MEDIUM, False),
    ("tcp", 554): ("rtsp", ACCURACY_LOW, False),
    ("udp", 554): ("rtsp", ACCURACY_LOW, False),
    ("udp", 67): ("dhcp", ACCURACY_MEDIUM, False),
    ("udp", 68): ("dhcp", ACCURACY_MEDIUM, False),
    ("udp", 5353): ("mdns", ACCURACY_MEDIUM, False),
    ("udp", 1900): ("ssdp", ACCURACY_MEDIUM, False),
    ("tcp", 445): ("smb", ACCURACY_LOW, False),
    ("tcp", 25): ("smtp", ACCURACY_LOW, False),
    ("tcp", 993): ("imaps_tls", ACCURACY_LOW, True),
    ("udp", 51820): ("wireguard_default_port", ACCURACY_LOW, False),
    ("udp", 1194): ("openvpn_default_port", ACCURACY_LOW, False),
}
_IP_PROTOCOLS: Final = {"icmp": "icmp", "icmpv6": "icmp", "ipv6-icmp": "icmp"}


@dataclass(frozen=True, slots=True)
class ProtocolGuess:
    """A heuristic protocol label (never proof of an application)."""

    label: str
    port: int | None
    basis: str
    accuracy: str
    notes: tuple[str, ...]
    heuristic: bool = True

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "label": self.label,
            "port": self.port,
            "basis": self.basis,
            "accuracy": self.accuracy,
            "heuristic": self.heuristic,
            "notes": list(self.notes),
        }


def _port(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= 65535 else None


def classify(proto: Any, src_port: Any = None, dst_port: Any = None) -> ProtocolGuess:
    """Heuristic label of a flow from transport and ports (see module doc)."""
    transport = proto.lower() if isinstance(proto, str) else ""
    if transport in _IP_PROTOCOLS:
        return ProtocolGuess(
            _IP_PROTOCOLS[transport], None, PROTO_BASIS_IP, ACCURACY_MEDIUM, ()
        )
    for port in (_port(dst_port), _port(src_port)):
        if port is None:
            continue
        known = KNOWN_PORTS.get((transport, port))
        if known is None:
            continue
        label, accuracy, tls = known
        notes = [NOTE_PORT_IS_NO_PROOF]
        if tls:
            notes.append(NOTE_TLS_NOT_ATTRIBUTED)
        return ProtocolGuess(label, port, PROTO_BASIS_PORT, accuracy, tuple(notes))
    return ProtocolGuess(
        PROTO_UNKNOWN, None, PROTO_BASIS_NONE, ACCURACY_NONE, (NOTE_PORT_IS_NO_PROOF,)
    )
