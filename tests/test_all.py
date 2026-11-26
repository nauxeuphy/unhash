from unhash.codecs_engine import run_recipe, auto_peel
from unhash.web_pentest import inspect_jwt, known_plaintext_xor

def test_natas8_auto_and_recipe():
    secret = "3d3d516343746d4d6d6c315669563362"
    assert run_recipe(secret, "hex,rev,b64")[-1][1] == "oubWYf2kBq"
    assert any(p[-1][1] == "oubWYf2kBq" for p in auto_peel(secret))

def test_natas11_xor_cookie_forgery():
    cookie = "ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw%3D"
    known_pt = '{"showpassword":"no","bgcolor":"#ffffff"}'
    forge_pt = '{"showpassword":"yes","bgcolor":"#ffffff"}'
    res = known_plaintext_xor(cookie, known_pt, forge_pt)
    assert res["repeating_key_str"] == "qw8J"
    assert res["forged_b64"] == "ClVLIh4ASCsCBE8lAxMacFMOXTlTWxooFhRXJh4FGnBTVF4sFxFeLFMK"

def test_jwt_audit():
    token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoibmF1ZmFsIiwiYWRtaW4iOmZhbHNlfQ."
    info = inspect_jwt(token)
    assert info["payload"]["user"] == "naufal"
    assert any("CRITICAL" in w for w in info["warnings"])
