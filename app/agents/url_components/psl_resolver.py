"""
psl_resolver.py
---------------
Offline, trie-based Public Suffix List (PSL) registered domain resolver.

Adheres strictly to the Mozilla Public Suffix List rules:
1. Exact match rules (e.g. 'com', 'co.uk').
2. Wildcard rules (e.g. '*.ck').
3. Exception rules (e.g. '!www.ck').
4. Unrecognized public suffixes evaluate to UNKNOWN_SUFFIX with registered_domain = None.
5. IP literals evaluate to IP_LITERAL with registered_domain = None.
6. Empty or missing hostnames evaluate to NO_HOSTNAME.
7. Malformed hostnames evaluate to INVALID_HOSTNAME.
"""

from __future__ import annotations

import functools
import hashlib
import ipaddress
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from app.schemas.url_agent_schema import DomainResolutionStatus


class PSLNode:
    """Node in the Public Suffix List reversed-label trie."""

    __slots__ = ("children", "is_rule", "is_wildcard", "is_exception")

    def __init__(self) -> None:
        self.children: Dict[str, PSLNode] = {}
        self.is_rule: bool = False
        self.is_wildcard: bool = False
        self.is_exception: bool = False


class PSLTrie:
    """
    In-memory trie indexing reversed PSL rule labels for fast O(L) domain resolution,
    where L is the number of labels in the hostname.
    """

    def __init__(self, dat_path: Path) -> None:
        self.root: PSLNode = PSLNode()
        self.dat_path: Path = dat_path
        self._load(dat_path)

    def _load(self, dat_path: Path) -> None:
        if not dat_path.is_file():
            raise FileNotFoundError(f"PSL data file not found: {dat_path}")

        with open(dat_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("//"):
                    continue

                is_exception = line.startswith("!")
                rule_str = line[1:].strip() if is_exception else line

                # Split rule into dot-separated labels and reverse
                labels = [lbl.lower() for lbl in rule_str.split(".") if lbl]
                if not labels:
                    continue

                rev_labels = labels[::-1]

                node = self.root
                for lbl in rev_labels:
                    if lbl not in node.children:
                        node.children[lbl] = PSLNode()
                    node = node.children[lbl]

                node.is_rule = True
                if is_exception:
                    node.is_exception = True
                elif rev_labels and rev_labels[-1] == "*":
                    node.is_wildcard = True

    def find_rule(self, labels: List[str]) -> Tuple[Optional[List[str]], Optional[str]]:
        """
        Match reversed labels against the PSL trie.
        Returns (matched_suffix_labels, rule_type) where rule_type is 'exception', 'wildcard', 'exact', or None.
        """
        rev = labels[::-1]
        matches: List[Tuple[List[str], bool, bool]] = []

        def dfs(node: PSLNode, idx: int, current_path: List[str]) -> None:
            if node.is_rule:
                matches.append((list(current_path), node.is_exception, node.is_wildcard))
            if idx >= len(rev):
                return
            lbl = rev[idx]

            # 1. Exact match child
            if lbl in node.children:
                dfs(node.children[lbl], idx + 1, current_path + [lbl])

            # 2. Wildcard child '*'
            if "*" in node.children:
                dfs(node.children["*"], idx + 1, current_path + ["*"])

            # 3. Exception child '!...'
            exc_key = "!" + lbl
            if exc_key in node.children:
                dfs(node.children[exc_key], idx + 1, current_path + [exc_key])

        dfs(self.root, 0, [])

        if not matches:
            return None, None

        # Hierarchy: Exception rules take absolute precedence
        for path, is_exc, _ in matches:
            if is_exc:
                # If !www.ck matched: the public suffix is 'ck' (exception rule minus the first label)
                suffix_rev = path[:-1]
                return suffix_rev[::-1], "exception"

        # Otherwise, rule with largest number of labels wins
        matches.sort(key=lambda m: len(m[0]), reverse=True)
        best_path, _, is_wild = matches[0]

        if is_wild:
            # Replace wildcard '*' with the actual matched label from domain
            # best_path has '*' at index -1
            actual_label = rev[len(best_path) - 1] if len(best_path) <= len(rev) else best_path[-1]
            suffix_rev = best_path[:-1] + [actual_label]
            return suffix_rev[::-1], "wildcard"

        return best_path[::-1], "exact"


@functools.lru_cache(maxsize=1)
def get_psl_trie() -> PSLTrie:
    """Obtain or initialize the global in-memory PSL trie singleton."""
    base_dir = Path(__file__).resolve().parent.parent.parent
    dat_path = base_dir / "data" / "public_suffix_list.dat"
    return PSLTrie(dat_path)


def resolve_domain(hostname: Optional[str]) -> Tuple[Optional[str], DomainResolutionStatus, int]:
    """
    Resolve a hostname string against the offline Public Suffix List.

    Returns:
        (registered_domain, domain_resolution_status, subdomain_depth)

    Specifications:
        - If hostname is None, empty, or whitespace -> (None, NO_HOSTNAME, 0)
        - If hostname is an IPv4 or IPv6 address literal -> (None, IP_LITERAL, 0)
        - If hostname contains invalid structural characters -> (None, INVALID_HOSTNAME, 0)
        - If public suffix matches:
            * Suffix takes all labels -> (None, status, 0)
            * Registered domain = 1 private label + suffix
            * Subdomain depth = count of labels preceding registered domain
        - If public suffix is unrecognized -> (None, UNKNOWN_SUFFIX, 0)
    """
    if hostname is None:
        return None, DomainResolutionStatus.NO_HOSTNAME, 0

    clean_host = hostname.strip().rstrip(".")
    if not clean_host:
        return None, DomainResolutionStatus.NO_HOSTNAME, 0

    # 1. IP literal check
    try:
        ipaddress.ip_address(clean_host)
        return None, DomainResolutionStatus.IP_LITERAL, 0
    except ValueError:
        pass

    # 2. Structural syntax validation
    if " " in clean_host or "\t" in clean_host or "\n" in clean_host or "\r" in clean_host:
        return None, DomainResolutionStatus.INVALID_HOSTNAME, 0

    # Check for invalid characters in host
    if any(c in clean_host for c in "/\\:?#@"):
        return None, DomainResolutionStatus.INVALID_HOSTNAME, 0

    # Punycode / IDNA normalization
    lower_host = clean_host.lower()
    try:
        lower_host = lower_host.encode("idna").decode("ascii")
    except Exception:
        pass

    labels = lower_host.split(".")
    # Empty labels (e.g. '..') are invalid
    if any(not lbl for lbl in labels):
        return None, DomainResolutionStatus.INVALID_HOSTNAME, 0

    # 3. PSL Matching
    trie = get_psl_trie()
    matched_suffix, rule_type = trie.find_rule(labels)

    if matched_suffix is None or rule_type is None:
        return None, DomainResolutionStatus.UNKNOWN_SUFFIX, 0

    suffix_len = len(matched_suffix)
    host_len = len(labels)

    if rule_type == "exception":
        status = DomainResolutionStatus.EXCEPTION_MATCH
    elif rule_type == "wildcard":
        status = DomainResolutionStatus.WILDCARD_MATCH
    else:
        status = DomainResolutionStatus.EXACT_MATCH

    # If the hostname matches the public suffix exactly or is shorter
    if host_len <= suffix_len:
        return None, status, 0

    # Registered domain includes 1 preceding private label
    reg_domain_labels = labels[-(suffix_len + 1) :]
    registered_domain = ".".join(reg_domain_labels)

    subdomain_labels = labels[: -(suffix_len + 1)]
    subdomain_depth = len(subdomain_labels)

    return registered_domain, status, subdomain_depth
