import json
import pytest


def test_register_begin(client):
    post = {"username": "hogehoge"}
    headers = {
        "Accept": "application/json, */*",
        "Content-type": "application/json",
    }
    r = client.post("/register/begin", json=post, headers=headers)
    assert r.status_code == 200, "200 OK"
    rjson = json.loads(r.get_data(as_text=True))
    assert rjson["rp"]["name"] == "Example WebAuthn", "rp.name = Example WebAuthn"
    assert rjson["user"]["name"] == "testUser", "user.name = testUser"
    assert rjson["user"]["displayName"] == "testUser", "user.displayName = testUser"
