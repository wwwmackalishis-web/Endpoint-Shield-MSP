"""Minimal in-memory rate limiter for POST /api/login.

Dependency-free on purpose, matching the project's existing bias toward
stdlib-only additions where a third-party package isn't earning its keep
(see app/notify.py's use of smtplib instead of a mailer library). Keyed by
(source IP, username) together, not either alone: keying on IP only would
let one guesser attacking many accounts from many IPs (or behind carrier-
grade NAT/a shared office IP) get an easier ride, while keying on username
only would let anyone lock a technician out of their own account by just
failing logins against their username from anywhere.

In-memory, single-process only: state resets on restart and is not shared
across multiple worker processes. That is an accepted limitation for the
current single-process deployment (see app/database.py's own SQLite-vs-
Postgres framing of "good enough for now, not for every future shape of
this deployment") - a multi-worker or multi-instance production deployment
should move this to a shared store (Redis, or a database-backed table)
rather than assume one process's memory is enough on its own.
"""

import time
from collections import deque
from typing import Deque, Dict, Optional, Tuple

MAX_ATTEMPTS = 5
WINDOW_SECONDS = 300  # 5 minutes

_attempts: Dict[Tuple[str, str], Deque[float]] = {}


def _key(source_ip: Optional[str], username: Optional[str]) -> Tuple[str, str]:
    return (source_ip or "unknown", username or "")


def check(source_ip: Optional[str], username: Optional[str]) -> bool:
    """True if this (ip, username) pair may still attempt a login.

    Read-only: does not itself record anything, so checking never counts as
    an attempt. Call record_failure() only after an actual failed login.
    """
    bucket = _attempts.get(_key(source_ip, username))
    if not bucket:
        return True
    now = time.monotonic()
    while bucket and now - bucket[0] > WINDOW_SECONDS:
        bucket.popleft()
    return len(bucket) < MAX_ATTEMPTS


def record_failure(source_ip: Optional[str], username: Optional[str]) -> None:
    key = _key(source_ip, username)
    bucket = _attempts.setdefault(key, deque())
    bucket.append(time.monotonic())


def record_success(source_ip: Optional[str], username: Optional[str]) -> None:
    """Clear the counter on a successful login.

    A technician who fat-fingered their password twice shouldn't be left
    one attempt away from a lockout the next time they actually need in.
    """
    _attempts.pop(_key(source_ip, username), None)
