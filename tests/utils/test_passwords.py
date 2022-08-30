import pytest

from api.utils import passwords


@pytest.mark.parametrize("password", ["", "foobar42", "Ai,982d$" * 256, "π"])
async def test__hash_password(password: str) -> None:
    res1 = await passwords.hash_password(password)
    res2 = await passwords.hash_password(password)

    assert res1 != res2
    assert passwords.password_hasher.verify(res1, password)
    assert passwords.password_hasher.verify(res1, password)


@pytest.mark.parametrize(
    "pw,guess,ok",
    [
        ("", "", True),
        ("", "x", False),
        ("foobar42", "foobar42", True),
        ("fooBar42", "foobar42", False),
        ("Ai,982d$" * 256, "Ai,982d$" * 256, True),
        ("Ai,982d$" * 256, "Ai,982d$" * 255, False),
        ("π", "π", True),
        ("π", "∞", False),
    ],
)
async def test__verify_password(pw: str, guess: str, ok: bool) -> None:
    pwhash = passwords.password_hasher.hash(pw)
    assert await passwords.verify_password(guess, pwhash) is ok
