"""fritzbox.py — Fritz!Box TR-064 DSL statistics client.

Polls the Fritz!Box modem via TR-064 UPnP/SOAP over HTTP.
Handles HTTP Digest MD5 authentication (Fritz!Box default).

Usage:
    stats = await get_dsl_stats(session, host, user, password)
    traffic = await get_wan_traffic(session, host, user, password)
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import xml.etree.ElementTree as ET
from typing import Any

import aiohttp

_LOGGER = logging.getLogger(__name__)

_TR064_PORT = 49000

_DSL_URL = "/upnp/control/wandslinterfaceconfig1"
_DSL_SERVICE = "urn:dslforum-org:service:WANDSLInterfaceConfig:1"
_DSL_ACTION = "GetDSLInfo"

_COMMON_URL = "/upnp/control/wancommonifconfig1"
_COMMON_SERVICE = "urn:dslforum-org:service:WANCommonInterfaceConfig:1"
_COMMON_ACTION = "GetAddonInfos"

_SOAP_TEMPLATE = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
    "<s:Body>"
    '<u:{action} xmlns:u="{service}"/>'
    "</s:Body>"
    "</s:Envelope>"
)


def _digest_header(
    uri: str,
    username: str,
    password: str,
    realm: str,
    nonce: str,
) -> str:
    """Compute HTTP Digest MD5 Authorization header."""
    nc = "00000001"
    cnonce = hashlib.md5(os.urandom(8)).hexdigest()[:8]
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"POST:{uri}".encode()).hexdigest()
    resp = hashlib.md5(
        f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode()
    ).hexdigest()
    return (
        f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
        f'uri="{uri}", qop=auth, nc={nc}, cnonce="{cnonce}", response="{resp}"'
    )


def _parse_soap(xml_text: str) -> dict[str, str]:
    """Return flat dict of all leaf-element values from a SOAP response."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}
    result: dict[str, str] = {}
    for elem in root.iter():
        if len(elem) == 0 and elem.text and elem.text.strip():
            tag = re.sub(r"\{[^}]+\}", "", elem.tag)
            result[tag] = elem.text.strip()
    return result


async def _soap_call(
    session: aiohttp.ClientSession,
    host: str,
    port: int,
    url_path: str,
    service: str,
    action: str,
    user: str,
    password: str,
    timeout: int = 8,
) -> dict[str, str]:
    """Make a TR-064 SOAP call with automatic Digest auth retry."""
    body = _SOAP_TEMPLATE.format(service=service, action=action).encode("utf-8")
    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": f'"{service}#{action}"',
    }
    url = f"http://{host}:{port}{url_path}"
    to = aiohttp.ClientTimeout(total=timeout)

    try:
        # Attempt 1: without auth (Fritz!Box allows this for some endpoints)
        async with session.post(url, data=body, headers=headers, timeout=to) as r:
            if r.status == 200:
                return _parse_soap(await r.text())
            if r.status not in (401, 500) or not user:
                _LOGGER.debug("Fritz!Box %s → HTTP %s", url_path, r.status)
                return {}
            www_auth = r.headers.get("WWW-Authenticate", "")

        # Attempt 2a: 401 with Digest challenge → use Digest auth
        realm_m = re.search(r'realm="([^"]+)"', www_auth)
        nonce_m = re.search(r'nonce="([^"]+)"', www_auth)
        if realm_m and nonce_m:
            headers["Authorization"] = _digest_header(
                url_path, user, password, realm_m.group(1), nonce_m.group(1)
            )
            async with session.post(url, data=body, headers=headers, timeout=to) as r:
                if r.status == 200:
                    return _parse_soap(await r.text())
                _LOGGER.debug("Fritz!Box Digest auth failed: HTTP %s", r.status)
                return {}

        # Attempt 2b: 500 without Digest challenge (some Fritz!Box firmware) → Basic auth
        # Fritz!Box supports both Basic and Digest; Basic avoids the nonce round-trip.
        async with session.post(
            url, data=body, headers=headers, timeout=to,
            auth=aiohttp.BasicAuth(user, password)
        ) as r:
            if r.status == 200:
                return _parse_soap(await r.text())
            # Basic rejected → grab Digest challenge from this 401 and retry
            if r.status == 401:
                www_auth2 = r.headers.get("WWW-Authenticate", "")
                realm_m2 = re.search(r'realm="([^"]+)"', www_auth2)
                nonce_m2 = re.search(r'nonce="([^"]+)"', www_auth2)
                if realm_m2 and nonce_m2:
                    h2 = dict(headers)
                    h2["Authorization"] = _digest_header(
                        url_path, user, password, realm_m2.group(1), nonce_m2.group(1)
                    )
                    async with session.post(url, data=body, headers=h2, timeout=to) as r:
                        if r.status == 200:
                            return _parse_soap(await r.text())
            _LOGGER.debug("Fritz!Box auth failed: HTTP %s", r.status)
            return {}

    except (aiohttp.ClientError, TimeoutError) as err:
        _LOGGER.debug("Fritz!Box unreachable: %s", err)
        return {}


def _i(data: dict[str, str], key: str) -> int:
    try:
        return int(data.get(key, 0))
    except (ValueError, TypeError):
        return 0


def _f(data: dict[str, str], key: str) -> float:
    try:
        return float(data.get(key, 0))
    except (ValueError, TypeError):
        return 0.0


async def get_dsl_stats(
    session: aiohttp.ClientSession,
    host: str,
    user: str = "",
    password: str = "",
    port: int = _TR064_PORT,
) -> dict[str, Any]:
    """Fetch DSL sync rates, SNR margin, and line attenuation.

    Returns empty dict if Fritz!Box is unreachable or auth fails.

    Keys:
        downstream_kbps   — downstream sync rate (kbps)
        upstream_kbps     — upstream sync rate (kbps)
        downstream_max_kbps — max attainable rate downstream
        upstream_max_kbps   — max attainable rate upstream
        snr_down_db       — downstream SNR margin (dB)
        snr_up_db         — upstream SNR margin (dB)
        attn_down_db      — downstream line attenuation (dB)
        attn_up_db        — upstream line attenuation (dB)
    """
    data = await _soap_call(
        session, host, port, _DSL_URL, _DSL_SERVICE, _DSL_ACTION, user, password
    )
    if not data:
        return {}
    # Fritz!Box reports noise margin / attenuation in 0.1 dB units
    return {
        "downstream_kbps": _i(data, "NewDownstreamCurrRate"),
        "upstream_kbps": _i(data, "NewUpstreamCurrRate"),
        "downstream_max_kbps": _i(data, "NewDownstreamMaxRate"),
        "upstream_max_kbps": _i(data, "NewUpstreamMaxRate"),
        "snr_down_db": round(_f(data, "NewDownstreamNoiseMargin") / 10.0, 1),
        "snr_up_db": round(_f(data, "NewUpstreamNoiseMargin") / 10.0, 1),
        "attn_down_db": round(_f(data, "NewDownstreamAttenuation") / 10.0, 1),
        "attn_up_db": round(_f(data, "NewUpstreamAttenuation") / 10.0, 1),
    }


async def get_wan_traffic(
    session: aiohttp.ClientSession,
    host: str,
    user: str = "",
    password: str = "",
    port: int = _TR064_PORT,
) -> dict[str, Any]:
    """Fetch realtime WAN byte rates from Fritz!Box.

    WANCommonInterfaceConfig#GetAddonInfos — often accessible without auth.

    Keys:
        downstream_bps  — current downstream throughput (bytes/s)
        upstream_bps    — current upstream throughput (bytes/s)
    """
    data = await _soap_call(
        session, host, port, _COMMON_URL, _COMMON_SERVICE, _COMMON_ACTION, user, password
    )
    if not data:
        return {}
    return {
        "downstream_bps": _i(data, "NewByteReceiveRate"),
        "upstream_bps": _i(data, "NewByteSendRate"),
    }
