import pytest
from app import encrypt_bytes, decrypt_bytes, scan_bytes
P="correct horse battery staple"
def test_round_trip():
    enc=encrypt_bytes(b"hello",P,"sample.txt"); plain,name=decrypt_bytes(enc,P)
    assert plain==b"hello" and name=="sample.txt"
def test_wrong_password():
    enc=encrypt_bytes(b"secret",P,"sample.txt")
    with pytest.raises(ValueError,match="Authentication failed"): decrypt_bytes(enc,"different strong password")
def test_tamper():
    enc=bytearray(encrypt_bytes(b"secret",P,"sample.txt")); enc[-1]^=1
    with pytest.raises(ValueError,match="Authentication failed"): decrypt_bytes(bytes(enc),P)
def test_bad_format():
    with pytest.raises(ValueError,match="not a supported"): decrypt_bytes(b"nope",P)
def test_scan_does_not_return_secret():
    result=scan_bytes(b'api_key = "this-is-a-demo-secret-value"',"config.py")
    assert result["findings"] and "this-is-a-demo-secret-value" not in str(result)
def test_binary_not_scanned():
    assert not scan_bytes(b"\\x00\\xff","photo.png")["scannable"]
