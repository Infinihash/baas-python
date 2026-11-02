"""Runs against production with no key: what does this rail actually offer?"""
from infinihash_baas import Rails, CapabilityUnavailable

r = Rails()
print("health:", r.health()["status"])
caps = r.capabilities()
print("settlement adapter:", caps["settlementAdapter"])
for name, c in caps["capabilities"].items():
    print("  %-24s %s" % (name, "available" if c.get("available") else "NOT available"))
try:
    r.require("managed_escrow")
except CapabilityUnavailable as e:
    print("as documented:", e)
