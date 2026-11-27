# infinihash-baas

Python SDK for **Infinihash Rails** (BaaS): invoices, ACH/stablecoin collection, settlement, signed records export.

    pip install "git+https://github.com/Infinihash/baas-python@v0.1.0"

```python
from infinihash_baas import Rails, SANDBOX_URL
r = Rails("ihb_...", base_url=SANDBOX_URL)      # build against the sandbox first
inv = r.create_invoice("INV-1", customer_id, [{"description": "Work", "unitCents": 25000}])
r.send_invoice(inv["id"])
r.pay_invoice(inv["id"], idempotency_key="INV-1-pay-1")   # retries never double-move money
```

- `Rails().capabilities()` / `require("...")` read what the host really offers (escrow and refunds are unavailable on every current deployment).
- `verify_webhook_signature(secret, raw_body, header)` is fail-closed.
- `create_sandbox_key(email)` gets a free, instant sandbox key (no sign-up); `examples/sandbox_quickstart.py` goes from nothing to a paid sandbox invoice.
- Examples: `examples/capabilities.py` (no key needed), `examples/sandbox_quickstart.py`, `examples/invoice_and_collect.py`.
- Reference: https://rails-api.infinihash.com/docs/openapi.public.json (public OpenAPI spec; the full `/api/docs` reference needs an API key). Get started: https://onboard.infinihash.com.

## Verifying a signed records export

`records_export()` returns parsed JSON, which **cannot** be verified because the signature covers the exact response bytes. For evidence you will verify or keep, use `records_export_signed()`:

```python
r = Rails("ihb_...")
exp = r.records_export_signed(from_="2026-01-01T00:00:00Z")   # format="csv" also works
# exp == {"body": b"...", "signature": "ed25519;keyid=...;sig=...", "key_id": "...", "sha256": "..."}
key = r.signing_key()            # {"alg": "ed25519", "keyId": ..., "publicKeyPem": ...}; no API key needed
assert exp["key_id"] == key["keyId"]
```

`signature` is the `X-Infinihash-Export-Signature` header: `ed25519;keyid=<id>;sig=<base64>` over the exact body bytes, or `unsigned` when the deployment has no signing key. Store `body` as-is. Re-serialising the JSON breaks the signature.

This SDK only depends on `requests`, so it does not verify Ed25519 itself. With the [`cryptography`](https://pypi.org/project/cryptography/) package installed:

```python
import base64
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from infinihash_baas import parse_export_signature

sig = base64.b64decode(parse_export_signature(exp["signature"])["sig"])
load_pem_public_key(key["publicKeyPem"].encode()).verify(sig, exp["body"])   # raises InvalidSignature if tampered
```

Or with OpenSSL 3: write `body` to `export.json`, the decoded `sig` to `export.sig` and `publicKeyPem` to `pub.pem`, then run `openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in export.json -sigfile export.sig`.
