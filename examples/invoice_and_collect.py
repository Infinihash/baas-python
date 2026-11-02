"""Create, send and collect an invoice. Use a sandbox key against SANDBOX_URL first.

    BAAS_API_KEY=ihb_... python examples/invoice_and_collect.py
"""
import os
from infinihash_baas import Rails, SANDBOX_URL

r = Rails(os.environ["BAAS_API_KEY"], base_url=os.environ.get("BAAS_URL", SANDBOX_URL))
inv = r.create_invoice("INV-0001", os.environ["BAAS_CUSTOMER_ID"],
                       [{"description": "Consulting", "quantity": 1, "unitCents": 25000}])
r.send_invoice(inv["id"])
print(r.pay_invoice(inv["id"], idempotency_key="INV-0001-pay-1"))  # safe to retry
