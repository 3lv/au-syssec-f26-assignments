import base64
import json
import sys
import requests
import math
from Crypto.Util.number import long_to_bytes

def json_to_cookie(j: str) -> str:
    """Encode json data in a cookie-friendly way using base64."""
    # The JSON data is a string -> encode it into bytes
    json_as_bytes = j.encode()
    # base64-encode the bytes
    base64_as_bytes = base64.b64encode(json_as_bytes, altchars=b'-_')
    # b64encode returns bytes again, but we need a string -> decode it
    base64_as_str = base64_as_bytes.decode()
    return base64_as_str

def main(base_url):
    msg = b'You got a 12 because you are an excellent student! :)'
    resp = requests.get(f"{base_url}/pk/")
    data = resp.json()
    N = data['N']
    print(f"N is equal to: {N}")

    M = int.from_bytes(msg, 'big')
    m1 = 2
    m2 = (M * pow(m1, -1, N)) % N
    M = m1 * m2 % N
    bytes_size = math.ceil(N.bit_length() / 8)

    m1_hex = m1.to_bytes(bytes_size, 'big').hex()
    m2_hex = m2.to_bytes(bytes_size, 'big').hex()

    print(f"m1 is equal to: {m1_hex}")

    resp1 = requests.get(f"{base_url}/sign_random_document_for_students/{m1_hex}")
    s1 = int(resp1.json()['signature'], 16)

    print(f"signature for message 1 is : {s1}")

    print(f"m2 is equal to: {m2_hex}")

    resp2 = requests.get(f"{base_url}/sign_random_document_for_students/{m2_hex}")
    s2 = int(resp2.json()['signature'], 16)

    print(f"signature for message 2 is : {s2}")

    final_signature = (s1 * s2) % N

    print(f"final signature is : {final_signature}")

    c = json_to_cookie(json.dumps({'msg': msg.hex(), 'signature': long_to_bytes(final_signature).hex() }))

    resp = requests.get(f'{base_url}/quote/', cookies={'grade': c})
    print(resp.text)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <base url>', file=sys.stderr)
        exit(1)
    main(sys.argv[1])
