#!/usr/bin/env python3

# CBC padding oracle attack
# - lenerd

import requests
import sys
import base64
import json
import math

def big_int_to_bytes(n: int) -> bytes:
    out_len = max(1, (n.bit_length() + 7) // 8)
    return n.to_bytes(out_len, "big")

def divide(b: bytes, div: int) -> bytes:
    n = int.from_bytes(b, "big") // div
    return big_int_to_bytes(n)

#def encrypt(base_url, b):
#    res = requests.get(f'{base_url}/encrypt_random_document_for_students/{b.hex()}')
#    data = res.json()
#    return data["ciphertext"]
def sign(base_url: str, b: bytes):
    res = requests.get(f'{base_url}/sign_random_document_for_students/{b.hex()}')
    data = res.json()
    return data["signature"]

def split_ct(c, p):
    len = math.ceil(p.bit_length() / 8)
    c = bytes.fromhex(c)
    a_1 = int.from_bytes(c[0:len], "big")
    a_2 = int.from_bytes(c[len:], "big")
    return (a_1, a_2)


def get_pk(base_url):
    res = requests.get(f'{base_url}/pk')
    data = res.json()
    return int(data["N"]), int(data["e"])

def json_to_cookie(j: str) -> str:
    """Encode json data in a cookie-friendly way using base64."""
    # The JSON data is a string -> encode it into bytes
    json_as_bytes = j.encode()
    # base64-encode the bytes
    base64_as_bytes = base64.b64encode(json_as_bytes, altchars=b'-_')
    # b64encode returns bytes again, but we need a string -> decode it
    base64_as_str = base64_as_bytes.decode()
    return base64_as_str

def obj_to_cookie(obj) -> str:
    return json_to_cookie(json.dumps(obj))

def submit_cookies(base_url, cookie):
    res = requests.get(f'{base_url}/quote/', cookies=cookie)
    print(res.text)


def test_systems_security(base_url):
    winning_msg = "You got a 12 because you are an excellent student! :)"
    winning_msg_number = int.from_bytes(winning_msg.encode(), "big")
    div = None
    for d in range(2, 1000):
        if winning_msg_number % d == 0:
            print(f"Found divisor {d}")
            div = d
            break

    if div == None:
        print("Didn't find divisor, abort")
        exit(1)
    
    message_div = divide(winning_msg.encode(), div)
    N, e = get_pk(base_url)

    s1 = bytes.fromhex(sign(base_url, div.to_bytes()))
    s2 = bytes.fromhex(sign(base_url, message_div))
    s1 = int.from_bytes(s1, "big")
    s2 = int.from_bytes(s2, "big")

    s = (s1 * s2) % N
    print("DEBUG: got the signiture s:", s)

    cookie_obj = {"msg": winning_msg.encode().hex(), "signature": big_int_to_bytes(s).hex()}
    
    cookie = obj_to_cookie(cookie_obj)
    submit_cookies(base_url, {"grade": cookie})


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <base url>', file=sys.stderr)
        exit(1)
    test_systems_security(sys.argv[1])
