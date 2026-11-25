"""
app/agents/text_components/intent_analyzer.py
---------------------------------------------
Deterministic intent, lure, and urgency cue extraction from email body text.
Offline, passive, and regex-grounded with zero external dependencies.
"""

from __future__ import annotations

import re
from typing import NamedTuple


# ---------------------------------------------------------------------------
# Pre-Compiled Phishing Intent Patterns
# ---------------------------------------------------------------------------

URGENCY_REGEX = re.compile(
    r"\b("
    r"immediately|urgent(?:ly)?|asap|act\s+now|immediate\s+action|"
    r"within\s+\d+\s*(?:hours?|hrs?|days?|mins?|minutes?)|"
    r"24\s*(?:hours?|hrs?)|48\s*(?:hours?|hrs?)|72\s*(?:hours?|hrs?)|"
    r"account\s+(?:has\s+been\s+|is\s+)?(?:suspended|terminated|blocked|disabled|locked)|"
    r"will\s+be\s+(?:suspended|terminated|blocked|disabled|closed|deleted)|"
    r"final\s+(?:notice|warning|reminder)|last\s+chance|limited\s+time|"
    r"time[- ]sensitive|expires?\s+(?:today|soon|in\s+\d+)"
    r")\b",
    re.IGNORECASE,
)

CREDENTIAL_LURE_REGEX = re.compile(
    r"\b("
    r"verify\s+(?:your\s+)?(?:account|password|identity|credentials|email|profile|details)|"
    r"update\s+(?:your\s+)?(?:account|password|identity|credentials|billing|payment|profile)|"
    r"confirm\s+(?:your\s+)?(?:identity|account|password|email|details)|"
    r"validate\s+(?:your\s+)?(?:account|credentials|email)|"
    r"reset\s+(?:your\s+)?(?:password|passcode|pin)|"
    r"login\s+(?:to\s+verify|here|immediately|below)|"
    r"sign\s*in\s+(?:to\s+verify|here|immediately|below)|"
    r"enter\s+(?:your\s+)?(?:credentials|password|passcode|pin)|"
    r"keep\s+your\s+(?:same\s+)?password|password\s+expires"
    r")\b",
    re.IGNORECASE,
)

FINANCIAL_LURE_REGEX = re.compile(
    r"\b("
    r"wire\s+transfer|bank\s+account|routing\s+number|direct\s+deposit|"
    r"cryptocurrency|bitcoin|btc|ethereum|eth|usdt|wallet\s+address|"
    r"overdue\s+invoice|unpaid\s+invoice|invoice\s+attached|remittance|"
    r"payment\s+(?:declined|failed|overdue|pending|processed|received)|"
    r"payroll\s+(?:update|issue|processing)|tax\s+refund|"
    r"billing\s+(?:problem|issue|failed|suspended)|card\s+declined"
    r")\b",
    re.IGNORECASE,
)

ACTION_LURE_REGEX = re.compile(
    r"\b("
    r"click\s+(?:here|below|the\s+link|this\s+link|on\s+the\s+link)|"
    r"follow\s+(?:the\s+)?link|open\s+(?:the\s+)?(?:attachment|file|document)|"
    r"download\s+(?:the\s+)?(?:attachment|file|document|invoice)|"
    r"press\s+here|tap\s+here|view\s+(?:document|invoice|statement|message)|"
    r"access\s+(?:your\s+)?(?:account|document|portal|message)"
    r")\b",
    re.IGNORECASE,
)

THREAT_CUE_REGEX = re.compile(
    r"\b("
    r"legal\s+action|law\s+enforcement|police|arrest|lawsuit|court\s+summons|"
    r"permanently\s+(?:closed|deleted|suspended|deactivated)|"
    r"unauthorized\s+access|security\s+breach|account\s+compromised|"
    r"security\s+alert|unrecognized\s+(?:device|login|activity)|"
    r"frozen\s+account|assets?\s+frozen|report(?:ed)?\s+to\s+authorities"
    r")\b",
    re.IGNORECASE,
)

REWARD_CUE_REGEX = re.compile(
    r"\b("
    r"congratulations|you\s+(?:have\s+)?won|lucky\s+winner|sweepstakes|"
    r"lottery|claim\s+(?:your\s+)?(?:prize|reward|bonus|funds|grant|refund)|"
    r"inheritance|unclaimed\s+(?:funds|money|property|package)|"
    r"cash\s+prize|cashback|free\s+(?:gift|voucher|money|reward)|"
    r"selected\s+for\s+a\s+(?:grant|payout|reward)|beneficiary"
    r")\b",
    re.IGNORECASE,
)


class IntentAnalysisResult(NamedTuple):
    urgency_cue_count: int
    has_urgency_cues: bool
    credential_lure_count: int
    has_credential_lures: bool
    financial_lure_count: int
    has_financial_lures: bool
    action_lure_count: int
    has_action_lures: bool
    threat_cue_count: int
    has_threat_cues: bool
    reward_cue_count: int
    has_reward_cues: bool
    matches_by_category: dict[str, list[str]]


def analyze_body_intent(text: str) -> IntentAnalysisResult:
    """
    Scan normalized email text and count matches across the 6 intent lure categories.
    """
    if not text or not text.strip():
        return IntentAnalysisResult(
            urgency_cue_count=0,
            has_urgency_cues=False,
            credential_lure_count=0,
            has_credential_lures=False,
            financial_lure_count=0,
            has_financial_lures=False,
            action_lure_count=0,
            has_action_lures=False,
            threat_cue_count=0,
            has_threat_cues=False,
            reward_cue_count=0,
            has_reward_cues=False,
            matches_by_category={},
        )

    urgency_matches = URGENCY_REGEX.findall(text)
    cred_matches = CREDENTIAL_LURE_REGEX.findall(text)
    fin_matches = FINANCIAL_LURE_REGEX.findall(text)
    action_matches = ACTION_LURE_REGEX.findall(text)
    threat_matches = THREAT_CUE_REGEX.findall(text)
    reward_matches = REWARD_CUE_REGEX.findall(text)

    matches_by_category = {
        "urgency": urgency_matches,
        "credential": cred_matches,
        "financial": fin_matches,
        "action": action_matches,
        "threat": threat_matches,
        "reward": reward_matches,
    }

    return IntentAnalysisResult(
        urgency_cue_count=len(urgency_matches),
        has_urgency_cues=bool(urgency_matches),
        credential_lure_count=len(cred_matches),
        has_credential_lures=bool(cred_matches),
        financial_lure_count=len(fin_matches),
        has_financial_lures=bool(fin_matches),
        action_lure_count=len(action_matches),
        has_action_lures=bool(action_matches),
        threat_cue_count=len(threat_matches),
        has_threat_cues=bool(threat_matches),
        reward_cue_count=len(reward_matches),
        has_reward_cues=bool(reward_matches),
        matches_by_category=matches_by_category,
    )
