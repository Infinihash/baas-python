"""Thin client for the Infinihash Rails (BaaS) API.

Design rules that mirror the service:
  * every money-moving POST carries an Idempotency-Key (generated if you do not
    pass one) so a retry can never move money twice;
  * capabilities are read from the host (GET /api/v1/capabilities), never
    assumed -- escrow and refunds are unavailable on every current deployment,
    and `require()` raises CapabilityUnavailable instead of letting you find out
    from a 409 in the middle of a flow;
  * webhook signatures are verified fail-closed.
"""
import hashlib
import hmac
import time
import uuid

import requests

PRODUCTION_URL = "https://rails-api.infinihash.com"
SANDBOX_URL = "https://rails-sandbox.infinihash.com"


class RailsError(Exception):
    def __init__(self, status, body):
        self.status, self.body = status, body
        code = body.get("code") if isinstance(body, dict) else None
        super().__init__("HTTP %s%s: %s" % (status, " " + code if code else "", body))


class CapabilityUnavailable(Exception):
    pass


def create_sandbox_key(email, base_url=SANDBOX_URL, timeout=30, session=None):
    """Get a free, instant sandbox API key (POST /api/v1/sandbox/keys). Sandbox host only.

    Returns the server's dict: ``apiKey`` (shown once), ``customerId`` (a starter customer to
    invoice), ``baseUrl``. The key works only on the sandbox host; production refuses it.
    """
    if base_url.rstrip("/") == PRODUCTION_URL.rstrip("/"):
        raise ValueError("sandbox keys are issued by the sandbox host, not production")
    return Rails(None, base_url=base_url, timeout=timeout, session=session)._request(
        "POST", "/api/v1/sandbox/keys", json={"email": email}, auth=False)


class Rails:
    def __init__(self, api_key=None, base_url=PRODUCTION_URL, timeout=30, session=None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._s = session or requests.Session()

    # -- transport ---------------------------------------------------------
    def _request(self, method, path, json=None, params=None, idempotency_key=None, auth=True):
        headers = {"Accept": "application/json"}
        if auth:
            if not self.api_key:
                raise ValueError("api_key is required for this call")
            headers["Authorization"] = "Bearer " + self.api_key
        if method == "POST":
            headers["Idempotency-Key"] = idempotency_key or str(uuid.uuid4())
        r = self._s.request(method, self.base_url + path, json=json, params=params,
                            headers=headers, timeout=self.timeout)
        try:
            body = r.json()
        except ValueError:
            body = {"raw": r.text}
        if r.status_code >= 400:
            raise RailsError(r.status_code, body)
        return body

    # -- public, no key ----------------------------------------------------
    def health(self):
        return self._request("GET", "/health", auth=False)

    def capabilities(self):
        return self._request("GET", "/api/v1/capabilities", auth=False)

    def require(self, capability):
        """Raise CapabilityUnavailable unless this host offers `capability`."""
        entry = self.capabilities().get("capabilities", {}).get(capability)
        if not entry or not entry.get("available"):
            raise CapabilityUnavailable("%s is not available on %s" % (capability, self.base_url))
        return entry

    # -- invoices ----------------------------------------------------------
    def create_invoice(self, number, customer_id, line_items, **fields):
        body = dict(fields, number=number, customerId=customer_id, lineItems=line_items)
        return self._request("POST", "/api/v1/invoices", json=body)

    def get_invoice(self, invoice_id):
        return self._request("GET", "/api/v1/invoices/%s" % invoice_id)

    def list_invoices(self, status=None):
        return self._request("GET", "/api/v1/invoices", params={"status": status} if status else None)

    def send_invoice(self, invoice_id):
        return self._request("POST", "/api/v1/invoices/%s/send" % invoice_id)

    def pay_invoice(self, invoice_id, amount_cents=None, source=None, idempotency_key=None):
        body = {}
        if amount_cents is not None:
            body["amountCents"] = amount_cents
        if source is not None:
            body["source"] = source
        return self._request("POST", "/api/v1/invoices/%s/pay" % invoice_id, json=body,
                             idempotency_key=idempotency_key)

    # -- statements and evidence ------------------------------------------
    def usage(self, month=None):
        return self._request("GET", "/api/v1/usage", params={"month": month} if month else None)

    def records_export(self):
        """Signed (Ed25519) tenant records export; verify with signing_key()."""
        return self._request("GET", "/api/v1/records/export")

    def signing_key(self):
        return self._request("GET", "/api/v1/records/signing-key", auth=False)


def verify_webhook_signature(secret, body, header, tolerance_seconds=300, now=None):
    """Verify `X-Infinihash-Signature: t=<unix>,v1=<hmac_sha256(secret, "<t>.<body>")>`.

    Fail-closed: returns False on any malformed header, stale timestamp or
    mismatch. `body` must be the raw request bytes/str, not re-serialised JSON.
    """
    try:
        parts = dict(p.split("=", 1) for p in header.split(","))
        t, v1 = int(parts["t"]), parts["v1"]
    except Exception:
        return False
    if abs((now if now is not None else time.time()) - t) > tolerance_seconds:
        return False
    raw = body if isinstance(body, bytes) else body.encode("utf-8")
    expected = hmac.new(secret.encode("utf-8"), str(t).encode() + b"." + raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, v1)
