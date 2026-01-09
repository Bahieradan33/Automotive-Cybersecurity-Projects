from src.security_access import derive_key_hmac_sha256, constant_time_compare


def test_derive_key_hmac_sha256() -> None:
    seed = bytes.fromhex("01020304")
    secret = b"SecretKey"
    expected_key = derive_key_hmac_sha256(seed, secret, out_length=4)
    assert isinstance(expected_key, bytes)
    assert len(expected_key) == 4


def test_constant_time_compare() -> None:
    assert constant_time_compare(b"\x01\x02", b"\x01\x02") is True
    assert constant_time_compare(b"\x01\x02", b"\x01\x03") is False