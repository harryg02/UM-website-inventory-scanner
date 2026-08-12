"""Decide whether an external domain actually belongs to the UM orbit.

This is the judgement call the inventory turns on. A UM affiliate site rarely
lives on umich.edu -- it is some .org or .com registered by a lab, a student
group, an alumni club or a hospital service line. No single signal settles it,
so we score several independent ones and bucket the total. Anything in the
middle is surfaced for a human rather than guessed at.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

AFFILIATED = "external-affiliated"
REVIEW = "external-review"
UNRELATED = "external-unrelated"

# Score at or above this is treated as UM-affiliated; below REVIEW_AT it is
# treated as unrelated. Between the two, a human should look.
AFFILIATED_AT = 6
REVIEW_AT = 3

_UM_REGENTS = re.compile(r"regents of the university of michigan", re.I)
_UM_NAME = re.compile(r"univ(ersity|\.)?\s+of\s+michigan|u\s*of\s*m\b", re.I)
_UM_HEALTH = re.compile(r"michigan medicine|u-?m health|umhs\b", re.I)
_UM_EMAIL = re.compile(r"@([a-z0-9\-]+\.)*umich\.edu$", re.I)
_ANN_ARBOR = re.compile(r"ann arbor,?\s*(mi|michigan)\b", re.I)

# Other Michigan institutions that share vocabulary but are not UM.
_RIVALS = re.compile(
    r"michigan state university|western michigan university|"
    r"eastern michigan university|central michigan university|"
    r"northern michigan university|michigan technological university|"
    r"wayne state university|grand valley state|oakland university|"
    r"state of michigan\b|michigan\.gov",
    re.I,
)

# Domain-name tokens, weighted by how much they actually imply UM.
_DOMAIN_TOKENS = [
    ("umich", 4),
    ("mgoblue", 3),
    ("goblue", 3),
    ("wolverine", 2),
    ("victors", 2),
    ("michiganmedicine", 4),
    ("umhealth", 3),
    ("michigan", 1),
    ("annarbor", 1),
]


@dataclass
class Evidence:
    """What the profiler managed to learn about a domain."""

    domain: str
    whois_org: str = ""
    whois_emails: list = field(default_factory=list)
    nameservers: list = field(default_factory=list)
    page_emails: list = field(default_factory=list)
    page_text: str = ""
    links_to_umich: bool = False


@dataclass
class Assessment:
    label: str
    score: int
    signals: list = field(default_factory=list)

    @property
    def reason(self) -> str:
        return "; ".join(self.signals) if self.signals else "no UM signals found"


def assess(ev: Evidence) -> Assessment:
    score = 0
    signals: list[str] = []

    def add(points: int, name: str) -> None:
        nonlocal score
        score += points
        signals.append(f"{name}({points:+d})")

    # --- registration data: the strongest evidence available ----------------
    org = ev.whois_org or ""
    if _UM_REGENTS.search(org):
        add(7, "whois-org-regents")
    elif _UM_NAME.search(org) or _UM_HEALTH.search(org):
        add(6, "whois-org-um")
    elif _RIVALS.search(org):
        add(-6, "whois-org-other-institution")

    if any(_UM_EMAIL.search(e) for e in ev.whois_emails):
        add(5, "whois-email-umich")

    # A domain served by UM's own DNS is UM-run whatever the registrar says.
    if any("umich" in ns for ns in ev.nameservers):
        add(4, "nameserver-umich")

    # --- addresses published on the site ------------------------------------
    if any(_UM_EMAIL.search(e) for e in ev.page_emails):
        add(4, "page-email-umich")

    # --- the domain name itself ---------------------------------------------
    bare = ev.domain.rsplit(".", 1)[0].replace("-", "").replace(".", "").lower()
    for token, weight in _DOMAIN_TOKENS:
        if token in bare:
            add(weight, f"domain-token-{token}")
            break

    # --- page content --------------------------------------------------------
    text = ev.page_text or ""
    if text:
        um_hits = len(_UM_NAME.findall(text)) + len(_UM_HEALTH.findall(text))
        rival_hits = len(_RIVALS.findall(text))

        if _UM_REGENTS.search(text):
            add(4, "page-regents-copyright")
        elif um_hits >= 3:
            add(3, "page-names-um-repeatedly")
        elif um_hits >= 1:
            add(2, "page-names-um")

        if rival_hits and rival_hits >= um_hits:
            add(-2, "page-favours-other-institution")

        if _ANN_ARBOR.search(text):
            add(1, "page-ann-arbor")

    if ev.links_to_umich:
        add(2, "links-to-umich")

    score = max(score, 0)
    if score >= AFFILIATED_AT:
        label = AFFILIATED
    elif score >= REVIEW_AT:
        label = REVIEW
    else:
        label = UNRELATED
    return Assessment(label, score, signals)
