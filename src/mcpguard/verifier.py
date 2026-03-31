"""Secret verification -- checks if detected secrets are actually live.

Makes minimal, read-only API calls to verify if a secret is valid.
Does NOT modify anything. Only checks authentication status.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class VerificationResult:
    """Result of verifying a single secret."""

    pattern: str
    verified: bool
    status: str  # "live", "invalid", "error", "skipped"
    detail: str = ""


# -- Verification functions ---------------------------------------------------

def verify_secret(value: str) -> VerificationResult:
    """Attempt to verify if a secret is live. Returns result."""
    # Skip env var references
    if value.startswith("${") or value.startswith("$"):
        return VerificationResult("ref", False, "skipped", "environment variable reference")

    for pattern, name, fn in _VERIFIERS:
        if re.match(pattern, value):
            try:
                return fn(value, name)
            except Exception as exc:
                return VerificationResult(name, False, "error", str(exc))

    return VerificationResult("unknown", False, "skipped", "no verifier available")


def _verify_github_pat(value: str, name: str) -> VerificationResult:
    """Check if a GitHub PAT is valid via /user endpoint."""
    req = urllib.request.Request(
        "https://api.github.com/user",
        headers={
            "Authorization": f"Bearer {value}",
            "User-Agent": "mcpguard-verifier/0.1",
            "Accept": "application/vnd.github.v3+json",
        },
    )
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        resp.read()  # consume response body
        if resp.status == 200:
            return VerificationResult(name, True, "live", "GitHub PAT is valid and active")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return VerificationResult(name, False, "invalid", "GitHub PAT is expired or revoked")
        if e.code == 403:
            return VerificationResult(name, True, "live", "GitHub PAT valid but rate limited")
    except (urllib.error.URLError, TimeoutError):
        return VerificationResult(name, False, "error", "Could not reach GitHub API")

    return VerificationResult(name, False, "error", "Unexpected response")


def _verify_openai_key(value: str, name: str) -> VerificationResult:
    """Check if an OpenAI API key is valid via /models endpoint."""
    req = urllib.request.Request(
        "https://api.openai.com/v1/models",
        headers={
            "Authorization": f"Bearer {value}",
            "User-Agent": "mcpguard-verifier/0.1",
        },
    )
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        if resp.status == 200:
            return VerificationResult(name, True, "live", "OpenAI key is valid")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return VerificationResult(name, False, "invalid", "OpenAI key is invalid")
        if e.code == 429:
            return VerificationResult(name, True, "live", "OpenAI key valid but rate limited")
    except (urllib.error.URLError, TimeoutError):
        return VerificationResult(name, False, "error", "Could not reach OpenAI API")

    return VerificationResult(name, False, "error", "Unexpected response")


def _verify_anthropic_key(value: str, name: str) -> VerificationResult:
    """Check if an Anthropic API key is valid."""
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        method="POST",
        headers={
            "x-api-key": value,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
            "User-Agent": "mcpguard-verifier/0.1",
        },
        data=b'{"model":"claude-3-haiku-20240307","max_tokens":1,"messages":[]}',
    )
    try:
        urllib.request.urlopen(req, timeout=5)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return VerificationResult(name, False, "invalid", "Anthropic key is invalid")
        if e.code in (400, 422, 429):
            # 400/422 = valid key but bad request (expected), 429 = rate limited
            return VerificationResult(name, True, "live", "Anthropic key is valid")
    except (urllib.error.URLError, TimeoutError):
        return VerificationResult(name, False, "error", "Could not reach Anthropic API")

    return VerificationResult(name, False, "error", "Unexpected response")


def _verify_stripe_key(value: str, name: str) -> VerificationResult:
    """Check if a Stripe key is valid via /charges endpoint."""
    req = urllib.request.Request(
        "https://api.stripe.com/v1/charges?limit=1",
        headers={
            "Authorization": f"Bearer {value}",
            "User-Agent": "mcpguard-verifier/0.1",
        },
    )
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        if resp.status == 200:
            return VerificationResult(name, True, "live", "Stripe key is valid")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return VerificationResult(name, False, "invalid", "Stripe key is invalid")
        if e.code == 429:
            return VerificationResult(name, True, "live", "Stripe key valid but rate limited")
    except (urllib.error.URLError, TimeoutError):
        return VerificationResult(name, False, "error", "Could not reach Stripe API")

    return VerificationResult(name, False, "error", "Unexpected response")


# -- Verifier registry --------------------------------------------------------

_VERIFIERS: list[tuple[str, str, callable]] = [
    (r"ghp_[a-zA-Z0-9]{36}", "github-pat", _verify_github_pat),
    (r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}", "github-fine-pat", _verify_github_pat),
    (r"gho_[a-zA-Z0-9]{36}", "github-oauth", _verify_github_pat),
    (r"sk-[a-zA-Z0-9\-]{20,}", "openai-key", _verify_openai_key),
    (r"sk-ant-[a-zA-Z0-9\-]{20,}", "anthropic-key", _verify_anthropic_key),
    (r"sk_live_[a-zA-Z0-9]{24,}", "stripe-live", _verify_stripe_key),
    (r"rk_live_[a-zA-Z0-9]{24,}", "stripe-restricted", _verify_stripe_key),
]
