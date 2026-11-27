import hashlib
import hmac
import pytest
from infinihash_baas import Rails, RailsError, CapabilityUnavailable, verify_webhook_signature


class FakeResp:
    def __init__(self, status, body):
        self.status_code, self._b, self.text = status, body, str(body)

    def json(self):
        return self._b


class FakeSession:
    def __init__(self, resp):
        self.resp, self.calls = resp, []

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        return self.resp


def test_post_always_carries_idempotency_key_and_bearer():
    s = FakeSession(FakeResp(200, {"id": "i1"}))
    Rails("ihb_x", session=s).pay_invoice("i1")
    h = s.calls[0][2]["headers"]
    assert h["Idempotency-Key"] and h["Authorization"] == "Bearer ihb_x"


def test_caller_idempotency_key_is_used_verbatim():
    s = FakeSession(FakeResp(200, {}))
    Rails("k", session=s).pay_invoice("i1", idempotency_key="abc")
    assert s.calls[0][2]["headers"]["Idempotency-Key"] == "abc"


def test_error_response_raises_with_code():
    with pytest.raises(RailsError) as e:
        Rails("k", session=FakeSession(FakeResp(409, {"code": "escrow_not_offered"}))).create_invoice("n", "c", [])
    assert e.value.status == 409 and "escrow_not_offered" in str(e.value)


def test_keyed_call_without_key_refuses_before_network():
    s = FakeSession(FakeResp(200, {}))
    with pytest.raises(ValueError):
        Rails(session=s).list_invoices()
    assert s.calls == []


def test_require_raises_when_capability_unavailable():
    s = FakeSession(FakeResp(200, {"capabilities": {"managed_escrow": {"available": False}}}))
    with pytest.raises(CapabilityUnavailable):
        Rails(session=s).require("managed_escrow")
    with pytest.raises(CapabilityUnavailable):
        Rails(session=s).require("not_a_thing")


def _sig(secret, t, body):
    return "t=%d,v1=%s" % (t, hmac.new(secret.encode(), str(t).encode() + b"." + body, hashlib.sha256).hexdigest())


def test_webhook_signature_valid_and_fail_closed():
    body = b'{"event":"settlement.completed"}'
    h = _sig("s3cret", 1000, body)
    assert verify_webhook_signature("s3cret", body, h, now=1100)
    assert not verify_webhook_signature("wrong", body, h, now=1100)
    assert not verify_webhook_signature("s3cret", body + b" ", h, now=1100)
    assert not verify_webhook_signature("s3cret", body, h, now=1000 + 301)   # stale
    assert not verify_webhook_signature("s3cret", body, "garbage", now=1100)
    assert not verify_webhook_signature("s3cret", body, "", now=1100)


def test_create_sandbox_key_posts_email_without_auth_and_refuses_production():
    from infinihash_baas import create_sandbox_key, PRODUCTION_URL
    s = FakeSession(FakeResp(201, {"apiKey": "ihb_sbx_x", "customerId": "c1"}))
    out = create_sandbox_key("a@example.com", session=s)
    method, url, kw = s.calls[0]
    assert (method, url) == ("POST", "https://rails-sandbox.infinihash.com/api/v1/sandbox/keys")
    assert kw["json"] == {"email": "a@example.com"}
    assert "Authorization" not in kw["headers"]
    assert out["apiKey"] == "ihb_sbx_x"
    with pytest.raises(ValueError):
        create_sandbox_key("a@example.com", base_url=PRODUCTION_URL, session=s)


# -- E-18: signed records export keeps the bytes and the signature ----------

class RawResp:
    def __init__(self, status, content, headers):
        self.status_code, self.content, self.headers = status, content, headers
        self.text = content.decode("utf-8", "replace")

    def json(self):
        import json
        return json.loads(self.content)


# Header shape from infinihash-baas src/lib/recordsExport.js (buildExport).
EXPORT_BODY = b'{\n  "tenantId": "t1",\n  "counts": {"invoices": 1}\n}\n'
EXPORT_SIG = "ed25519;keyid=0123456789abcdef;sig=" + "QUJD" * 21 + "QQ=="
EXPORT_SHA = hashlib.sha256(EXPORT_BODY).hexdigest()


def test_records_export_signed_returns_raw_body_signature_and_key_id():
    s = FakeSession(RawResp(200, EXPORT_BODY, {
        "X-Infinihash-Export-Signature": EXPORT_SIG,
        "X-Infinihash-Export-SHA256": EXPORT_SHA,
    }))
    out = Rails("k", session=s).records_export_signed(from_="2026-01-01T00:00:00Z", format="csv")
    assert out == {"body": EXPORT_BODY, "signature": EXPORT_SIG,
                   "key_id": "0123456789abcdef", "sha256": EXPORT_SHA}
    method, url, kw = s.calls[0]
    assert (method, url) == ("GET", "https://rails-api.infinihash.com/api/v1/records/export")
    assert kw["params"] == {"from": "2026-01-01T00:00:00Z", "format": "csv"}
    assert kw["headers"]["Authorization"] == "Bearer k"


def test_records_export_signed_unsigned_deployment():
    s = FakeSession(RawResp(200, EXPORT_BODY, {"X-Infinihash-Export-Signature": "unsigned"}))
    out = Rails("k", session=s).records_export_signed()
    assert out["signature"] == "unsigned" and out["key_id"] is None and out["body"] == EXPORT_BODY
    assert s.calls[0][2]["params"] is None


def test_records_export_signed_error_raises_and_needs_key():
    s = FakeSession(RawResp(401, b'{"code": "unauthorized"}', {}))
    with pytest.raises(RailsError) as e:
        Rails("k", session=s).records_export_signed()
    assert e.value.status == 401
    with pytest.raises(ValueError):
        Rails(session=FakeSession(None)).records_export_signed()


def test_records_export_is_unchanged_parsed_json():
    s = FakeSession(FakeResp(200, {"tenantId": "t1"}))
    assert Rails("k", session=s).records_export() == {"tenantId": "t1"}


def test_parse_export_signature():
    from infinihash_baas import parse_export_signature
    p = parse_export_signature(EXPORT_SIG)
    assert p["alg"] == "ed25519" and p["keyid"] == "0123456789abcdef" and p["sig"].endswith("QQ==")
    for bad in (None, "", "unsigned", "hmac;sig=x", "ed25519;keyid=a"):
        assert parse_export_signature(bad) == {}
