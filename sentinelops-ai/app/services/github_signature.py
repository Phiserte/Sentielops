import hashlib
import hmac
import os


def verify_signature(payload: bytes, signature: str | None) -> bool:
    """
    Verify GitHub webhook signature using HMAC SHA-256.
    """

    if signature is None:
        return False

    secret = os.getenv("GITHUB_WEBHOOK_SECRET")

    if not secret:
        raise ValueError("GITHUB_WEBHOOK_SECRET is not configured")

    expected_signature = (
        "sha256="
        + hmac.new(
            secret.encode("utf-8"),
            payload,
            hashlib.sha256,
        ).hexdigest()
    )

    return hmac.compare_digest(expected_signature, signature)