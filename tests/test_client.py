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
