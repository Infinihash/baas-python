"""Zero to a settled sandbox invoice with no sign-up: get a key, invoice, pay.

    python examples/sandbox_quickstart.py you@example.com

Runs against https://rails-sandbox.infinihash.com (mock settlement and mock screening: no real
money moves, nothing is emailed). The sandbox key is shown once; it works only on the sandbox host.
"""
import sys
import uuid

from infinihash_baas import Rails, RailsError, create_sandbox_key, SANDBOX_URL

email = sys.argv[1] if len(sys.argv) > 1 else "dev-%s@example.com" % uuid.uuid4().hex[:8]
grant = create_sandbox_key(email)
print("sandbox key issued for tenant", grant["tenantId"], "(keep it; it is not shown again)")

r = Rails(grant["apiKey"], base_url=SANDBOX_URL)
print("adapter:", r.capabilities().get("settlementAdapter"))

inv = r.create_invoice("SBX-0001", grant["customerId"],
                       [{"description": "Sandbox consulting", "quantity": 1, "unitCents": 25000}])
r.send_invoice(inv["id"])
try:
    print(r.pay_invoice(inv["id"], idempotency_key="SBX-0001-pay-1"))  # safe to retry
except RailsError as e:
    print("pay declined or pending:", e.status, e.body)
