from secure_ai.pii_filter import SECRET_KINDS, find_secrets, has_secret, redact


def kinds(text, **kw):
    return set(redact(text, **kw).findings)


def test_email_phone_indian():
    r = redact("mail me at a.b@x.co.in or call +91 98765 43210 / 9876543210")
    assert "[REDACTED:EMAIL]" in r.text and r.findings["PHONE"] == 2 or "PHONE" in r.findings


def test_aadhaar_and_pan():
    r = redact("Aadhaar 2345 6789 0123, PAN ABCDE1234F")
    assert r.findings == {"AADHAAR": 1, "PAN": 1}


def test_credit_card_luhn():
    assert "CREDIT_CARD" in kinds("card 4111 1111 1111 1111")
    assert "CREDIT_CARD" not in kinds("order 4111 1111 1111 1112")     # fails Luhn


def test_ssn():
    assert "SSN" in kinds("ssn 123-45-6789")


def test_secrets_detected():
    samples = {
        "API_KEY": "sk-ant-abcdefghijklmnopqrstuvwx1234",
        "AWS_ACCESS_KEY": "AKIAABCDEFGHIJKLMNOP",
        "GITHUB_TOKEN": "ghp_" + "a" * 36,
        "JWT": "eyJhbGciOiJI.eyJzdWIiOiIxMjM0.abcdefghijkl",
        "PRIVATE_KEY": "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----",
        "SECRET_ASSIGNMENT": "password = hunter2hunter2",
    }
    for kind, s in samples.items():
        assert kind in kinds(s), kind
        assert has_secret(s)
    assert set(SECRET_KINDS) >= set(samples)


def test_secret_never_survives():
    out = redact("key=sk-ant-abcdefghijklmnopqrstuvwx1234 end").text
    assert "abcdefghijkl" not in out


def test_kind_filter_keeps_email():
    r = redact("bob@acme.com card 4111 1111 1111 1111", kinds={"CREDIT_CARD"})
    assert "bob@acme.com" in r.text and "4111" not in r.text


def test_clean_text_untouched():
    t = "Refunds are processed within 7 days."
    assert redact(t).text == t and find_secrets(t) == []


def test_ten_digit_number_not_starting_6_to_9_is_not_phone():
    assert "PHONE" not in kinds("ref 1234567890")
