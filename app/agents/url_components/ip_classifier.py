"""
ip_classifier.py
----------------
Deterministic 9-category RFC IP classification engine for the URL Agent.

Categorizes IPv4 and IPv6 addresses in strict accordance with Section 5.3 of the
Phase B implementation plan, handling longest-prefix matching, IPv4-mapped IPv6 unwrap,
and explicit global overrides.
"""

from __future__ import annotations

import ipaddress
from typing import Optional, Union

from app.schemas.url_agent_schema import IPClassificationCategory


# Pre-compiled IPv4 network objects for high performance
_IPV4_GLOBAL_OVERRIDES = (
    ipaddress.ip_address("192.0.0.9"),
    ipaddress.ip_address("192.0.0.10"),
)
_IPV4_LOOPBACK = ipaddress.ip_network("127.0.0.0/8")
_IPV4_LINK_LOCAL = ipaddress.ip_network("169.254.0.0/16")
_IPV4_MULTICAST = ipaddress.ip_network("224.0.0.0/4")
_IPV4_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_IPV4_DOC_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)
_IPV4_SPECIAL_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("240.0.0.0/4"),
)
_IPV4_RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

# Pre-compiled IPv6 network objects
_IPV6_LOOPBACK = ipaddress.ip_address("::1")
_IPV6_UNSPECIFIED = ipaddress.ip_address("::")
_IPV6_LINK_LOCAL = ipaddress.ip_network("fe80::/10")
_IPV6_MULTICAST = ipaddress.ip_network("ff00::/8")
_IPV6_DOC_NETWORKS = (
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("3fff::/20"),
)

# 2001::/23 Longest-Prefix Matching
_IPV6_2001_PARENT = ipaddress.ip_network("2001::/23")
_IPV6_2001_GLOBAL_SPECIFIC_IPS = (
    ipaddress.ip_address("2001:1::1"),
    ipaddress.ip_address("2001:1::2"),
    ipaddress.ip_address("2001:1::3"),
)
_IPV6_2001_GLOBAL_NETWORKS = (
    ipaddress.ip_network("2001:3::/32"),
    ipaddress.ip_network("2001:4:112::/48"),
    ipaddress.ip_network("2001:20::/28"),
    ipaddress.ip_network("2001:30::/28"),
)
_IPV6_2001_SPECIAL_NETWORKS = (
    ipaddress.ip_network("2001::/32"),    # TEREDO
    ipaddress.ip_network("2001:2::/48"),  # Benchmarking
    ipaddress.ip_network("2001:10::/28"), # Deprecated
)

# IPv6 Outside 2001::/23
_IPV6_SPECIAL_OUTSIDE_2001 = (
    ipaddress.ip_network("64:ff9b:1::/48"),
    ipaddress.ip_network("100::/64"),
    ipaddress.ip_network("100:0:0:1::/64"),
    ipaddress.ip_network("2002::/16"),
    ipaddress.ip_network("5f00::/16"),
)
_IPV6_EXPLICIT_GLOBAL_NETWORKS = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("2620:4f:8000::/48"),
)
_IPV6_RFC4193_ULA = ipaddress.ip_network("fc00::/7")
_IPV6_2000_GLOBAL_UNICAST = ipaddress.ip_network("2000::/3")


def classify_ip_address(ip_input: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> IPClassificationCategory:
    """
    Classify an IPv4 or IPv6 address literal into the approved 9 RFC categories.
    Follows Section 5.3 exact precedence order.
    """
    if isinstance(ip_input, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        ip = ip_input
    else:
        ip = ipaddress.ip_address(ip_input.strip().strip("[]"))

    # 1. Unwrap IPv4-Mapped IPv6 (::ffff:0:0/96)
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    # -----------------------------------------------------------------------
    # IPv4 Precedence Hierarchy
    # -----------------------------------------------------------------------
    if ip.version == 4:
        # Precedence 1: More-specific global overrides (RFC 7723 / RFC 8155)
        if ip in _IPV4_GLOBAL_OVERRIDES:
            return "syntactically_global"

        # Precedence 2: Loopback (RFC 1122)
        if ip in _IPV4_LOOPBACK:
            return "loopback"

        # Precedence 3: Link-Local (RFC 3927)
        if ip in _IPV4_LINK_LOCAL:
            return "link_local"

        # Precedence 4: Multicast (RFC 5771)
        if ip in _IPV4_MULTICAST:
            return "multicast"

        # Precedence 5: Carrier-Grade NAT (RFC 6598)
        if ip in _IPV4_CGNAT:
            return "cgnat"

        # Precedence 6: Documentation (RFC 5737)
        if any(ip in net for net in _IPV4_DOC_NETWORKS):
            return "documentation"

        # Precedence 7: Special-Purpose / Reserved (RFC 6890 / RFC 1112)
        if any(ip in net for net in _IPV4_SPECIAL_NETWORKS):
            return "special_purpose"

        # Precedence 8: RFC 1918 Private
        if any(ip in net for net in _IPV4_RFC1918_NETWORKS):
            return "rfc1918"

        # Precedence 9: Global Routable Fallback
        return "syntactically_global"

    # -----------------------------------------------------------------------
    # IPv6 Precedence Hierarchy
    # -----------------------------------------------------------------------
    # Precedence 1: Loopback (RFC 4291)
    if ip == _IPV6_LOOPBACK:
        return "loopback"

    # Precedence 2: Link-Local (RFC 4291)
    if ip in _IPV6_LINK_LOCAL:
        return "link_local"

    # Precedence 3: Multicast (RFC 4291 / IANA IPv6 Address Space)
    if ip in _IPV6_MULTICAST:
        return "multicast"

    # Precedence 4: Documentation (RFC 3849 / RFC 6666)
    if any(ip in net for net in _IPV6_DOC_NETWORKS):
        return "documentation"

    # Precedence 5: 2001::/23 Longest-Prefix Matching
    if ip in _IPV6_2001_PARENT:
        if ip in _IPV6_2001_GLOBAL_SPECIFIC_IPS or any(ip in net for net in _IPV6_2001_GLOBAL_NETWORKS):
            return "syntactically_global"
        if any(ip in net for net in _IPV6_2001_SPECIAL_NETWORKS):
            return "special_purpose"
        # Parent /23 remainder default
        return "special_purpose"

    # Precedence 6: Special-Purpose outside 2001::/23
    if ip == _IPV6_UNSPECIFIED or any(ip in net for net in _IPV6_SPECIAL_OUTSIDE_2001):
        return "special_purpose"

    # Precedence 7: Explicit Global Allocations
    if any(ip in net for net in _IPV6_EXPLICIT_GLOBAL_NETWORKS):
        return "syntactically_global"

    # Precedence 8: RFC 4193 Unique Local IPv6 (ULA)
    if ip in _IPV6_RFC4193_ULA:
        return "rfc4193"

    # Precedence 9: 2000::/3 Global Unicast Block Fallback
    if ip in _IPV6_2000_GLOBAL_UNICAST:
        return "syntactically_global"

    # Precedence 10: Unallocated / Reserved Fallback
    return "special_purpose"
