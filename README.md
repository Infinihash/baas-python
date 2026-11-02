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
- Reference: https://rails-api.infinihash.com/api/docs. Get started: https://onboard.infinihash.com.
