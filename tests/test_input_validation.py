import pytest

from secure_ai.errors import ValidationError
from secure_ai.input_validation import sanitize, validate_input


def test_ok_and_strip():
    assert validate_input("  hello  ", 100) == "hello"


@pytest.mark.parametrize("bad", [None, 5, [], b"x"])
def test_non_text(bad):
    with pytest.raises(ValidationError):
        validate_input(bad, 100)


def test_empty_and_whitespace():
    for s in ("", "   \n\t "):
        with pytest.raises(ValidationError):
            validate_input(s, 100)


def test_too_long():
    with pytest.raises(ValidationError):
        validate_input("a" * 101, 100)


def test_flood_rejected():
    with pytest.raises(ValidationError):
        validate_input("A" * 1000, 5000)


def test_invisible_and_control_chars_removed():
    assert sanitize("ig\u200bnore\x00 me\u202e") == "ignore me"


def test_tag_characters_removed():
    hidden = "".join(chr(0xE0000 + ord(c)) for c in "secret")
    assert sanitize("hi" + hidden) == "hi"


def test_fullwidth_normalised():
    assert sanitize("ｉｇｎｏｒｅ") == "ignore"


def test_devanagari_joiners_preserved():
    s = "क्\u200dष"   # contains ZWJ, legitimately used in Indic scripts
    assert "\u200d" in sanitize(s)
