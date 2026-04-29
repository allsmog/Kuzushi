"""PoC: seer_rpc.compare_signature ignores the URL parameter.

Faithfully mirrors src/sentry/seer/endpoints/seer_rpc.py:149-189 in
getsentry/sentry@master, with settings.SEER_RPC_SHARED_SECRET stubbed
to a local list so the function is runnable without a Sentry checkout.
"""
import hashlib
import hmac

SHARED_SECRETS = ["test-secret-not-real"]  # stand-in for settings.SEER_RPC_SHARED_SECRET


def compare_signature(url: str, body: bytes, signature: str) -> bool:
    if not SHARED_SECRETS:
        raise RuntimeError("SEER_RPC_SHARED_SECRET not configured")
    if not signature.startswith("rpc0:"):
        return False
    if not body:
        return False
    try:
        _, signature_data = signature.split(":", 2)
        signature_input = body  # <- bug: `url` parameter is dropped
        for key in SHARED_SECRETS:
            computed = hmac.new(key.encode(), signature_input, hashlib.sha256).hexdigest()
            if hmac.compare_digest(computed.encode(), signature_data.encode()):
                return True
    except Exception:
        return False
    return False


def sign(body: bytes, secret: str) -> str:
    return f"rpc0:{hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()}"


secret = SHARED_SECRETS[0]
body = b'{"args":{"organization_id":42}}'
sig = sign(body, secret)
print(f"signature for body {body!r}: {sig}")
for url in (
    "/seer-rpc/get_organization_slug/",
    "/seer-rpc/trigger_coding_agent_launch/",
    "/seer-rpc/send_seer_webhook/",
):
    print(f"  {url:42s} verifies: {compare_signature(url, body, sig)}")
