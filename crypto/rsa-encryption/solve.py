#!/usr/bin/env python3

# CBC padding oracle attack
# - lenerd

import requests
import sys
import base64
import json
import math

def multiply_messages(m1: bytes, m2: bytes, n: int):
    m1 = int.from_bytes(m1, "big")
    m2 = int.from_bytes(m2, "big")
    out_len = max(1, (n.bit_length() + 7) // 8)
    res = (m1 * m2) % n
    return res.to_bytes(out_len, "big")

def encrypt(message: bytes, n: int, e: int) -> bytes:
    #res = requests.get(f'{base_url}/encrypt_random_document_for_students/{b.hex()}')
    message = int.from_bytes(message, "big")
    res = pow(message, e, n)
    out_len = max(1, (n.bit_length() + 7) // 8)
    res = res.to_bytes(out_len, "big")
    return res

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

def submit_cookies(base_url, cookies):
    res = requests.get(f'{base_url}/quote/', cookies=cookies)
    return res.text

def mod_2_of_message(base_url: str, ciphertext: bytes):
    res: str = submit_cookies(base_url, {"authtoken": ciphertext.hex()})
    if res.lower().endswith("do not like even numbers."):
        return 0
    return 1

def test_systems_security(base_url):
    #winning_msg = "You got a 12 because you are an excellent student! :)"
    #print("Locally computed:", int.from_bytes(winning_msg.encode(), "big") % 2)
    #c1 = encrypt(winning_msg.encode(), n, e)

    auth_token = bytes.fromhex("c23041e62b82c735428d864d52339e774287079322ece21b9de1ee1937175749fcfcf57b71e84e2574636a1af2ca130bb1f4a7bee21089bbbed10b4c964a967ca5850c0342695b629b72b2188060a29c46400de923711e98b2808e7e3533c56e971fbb33cafb8a02b9ff0af5009d02f60225ba2891892a8ed120ba31bbd712527aa311e6a7af8c77c08d4277bec01fd8c31f3939cd022710559055f1bd712b085c94a1daaeeb836ae9c3f3e6cd60967b034383194e135d92d9ba261a0c71f91b67d041bea83fae790044f94790a0b1d4f55167622679d761f22db4f51e7403f4fbe76e45189f6df2afce0a1cbda88e27afeeee5760cadd3c28c4895c6c0dd7b1bb84f4720fac43a816063ac648e4e6b00f44d467e063354d07cfdec73288b128c42312ab45eb1b1ed451858cfdf4cde9afbbf521c387ecd2c411d2a35ccb5926b57821c4a50e488d14376f9c6bac3edfbbbb45b5d2edf8f6b5dfbc781663a8324a0a11b19a2564990dc37055a10d501d6eba1613c4efee43e47af6169c93eb0c")
    current_number = int.from_bytes(auth_token, "big")

    (n, e) = get_pk(base_url)
    out_len = max(1, (n.bit_length() + 7) // 8)
    mult_2 = pow(2, e, n)

    other_part = 0

    powers = []
    left = 0
    right = n
    current_number = (current_number * mult_2) % n
    mod_2 = mod_2_of_message(base_url, current_number.to_bytes(out_len, "big"))
    if mod_2 == 0:
        right = (left + right) // 2
    else:
        # Did wrap the modulus
        other_part += n
    other_part *= 2

    print(mod_2)
    bits.append(mod_2)
    mod_2 = mod_2_of_message(base_url, current_number.to_bytes(out_len, "big"))
    while mod_2 == 0:
        current_number = (current_number * mult_2) % n
        mod_2 = mod_2_of_message(base_url, current_number.to_bytes(out_len, "big"))
        print(mod_2)
    exit(1)


    multiply_messages(auth_token, div_2)
    print("From server", c1_mod_2)
    exit()


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
