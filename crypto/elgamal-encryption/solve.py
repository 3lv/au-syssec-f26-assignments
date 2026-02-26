#!/usr/bin/env python3

# CBC padding oracle attack
# - lenerd

import requests
import sys
import base64
import json
import math

def multiply_by_2(b):
    n = int.from_bytes(b, "big") * 2
    out_len = max(1, (n.bit_length() + 7) // 8)
    return n.to_bytes(out_len, "big")

def encrypt(base_url, b):
    res = requests.get(f'{base_url}/encrypt_random_document_for_students/{b.hex()}')
    data = res.json()
    return data["ciphertext"]

def split_ct(c, p):
    len = math.ceil(p.bit_length() / 8)
    c = bytes.fromhex(c)
    a_1 = int.from_bytes(c[0:len], "big")
    a_2 = int.from_bytes(c[len:], "big")
    return (a_1, a_2)


def get_p(base_url):
    res = requests.get(f'{base_url}/params')
    data = res.json()
    return data["p"]

def lgpow(b, e, modulo):
    result = 1
    base = b
    while e > 0:
        if e & 1:
            result = (result * base) % modulo
        base = (base * base) % modulo
        e >>= 1
    return result

def json_to_cookie(j: str) -> str:
    """Encode json data in a cookie-friendly way using base64."""
    # The JSON data is a string -> encode it into bytes
    json_as_bytes = j.encode()
    # base64-encode the bytes
    base64_as_bytes = base64.b64encode(json_as_bytes, altchars=b'-_')
    # b64encode returns bytes again, but we need a string -> decode it
    base64_as_str = base64_as_bytes.decode()
    return base64_as_str

def submit_cookies(base_url, cookie):
    res = requests.get(f'{base_url}/quote/', cookies=cookie)
    print(res.text)


def test_systems_security(base_url):
    winning_msg = "You got a 12 because you are an excellent student! :)"
    p = int(get_p(base_url))
    c2 = encrypt(base_url, bytes([2]))
    c3 = encrypt(base_url, multiply_by_2(winning_msg.encode()))
    # (g ^ y, m * h ^ y)
    (a2_1, a2_2) = split_ct(c2, p)
    (a3_1, a3_2) = split_ct(c3, p)
    #c1 = c3 / c2
    a1_1 = (a3_1 * lgpow(a2_1, p - 2, p)) % p
    a1_2 = (a3_2 * lgpow(a2_2, p - 2, p)) % p

    print("a1:", (a1_1, a1_2))

    c1_1 = a1_1.to_bytes(math.ceil(p.bit_length() / 8), 'big').hex()
    c1_2 = a1_2.to_bytes(math.ceil(p.bit_length() / 8), 'big').hex()
    ciphertext = c1_1 + c1_2
    
    cookie = json_to_cookie(json.dumps({"ciphertext": ciphertext}))
    submit_cookies(base_url, {"grade": cookie})


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <base url>', file=sys.stderr)
        exit(1)
    test_systems_security(sys.argv[1])
