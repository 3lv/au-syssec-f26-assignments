import requests
import json
import secrets
import base64


server = "http://127.0.0.1:5000/"


# try to get quote without having grade 12
response = requests.get(server)
cookies = response.cookies
response = requests.get(server + "quote", cookies=cookies)

print("try to get quote without having grade 12:")
print(response.text)
print("\n")


# ATTACK
# get p
response = requests.get(server+"params")
response_json = json.loads(response.text)
p = response_json["p"]

# get random r
r = secrets.randbelow(p-1) + 1
r_inv = pow(r, -1, p)

# target message that is needed to get a quote
M = "You got a 12 because you are an excellent student! :)".encode()
M_int = int.from_bytes(M, "big")

# get disguised message and convert to hex
M_prime = (M_int * r_inv) % p

M_prime_len = (M_prime.bit_length()+7) // 8
M_prime_bytes = M_prime.to_bytes(M_prime_len, "big") 
M_prime_hex = M_prime_bytes.hex() 

# get ciphertext for M_prime
response = requests.get(server+"encrypt_random_document_for_students/"+M_prime_hex)
ct = bytes.fromhex(json.loads(response.text)["ciphertext"])

# get c1 and c2 from ct (concatenation of c1 and c2)
L = (p.bit_length()+7) // 8
c1_bytes = ct[:L]
c2_bytes = ct[L:2*L]
c2 = int.from_bytes(c2_bytes, "big")

# compute ciphertext of M
c2_M = (c2 * r) % p
c2_M_bytes = c2_M.to_bytes(L, "big")
cipher_m = c1_bytes + c2_M_bytes
cipher_m_hex = cipher_m.hex()

# Encode cookie in same way the server does it
msg_json = json.dumps({
    'msg': M.hex(),  # The actual message
    'ciphertext': cipher_m_hex
})

cookie_value = base64.b64encode(msg_json.encode(), altchars=b'-_').decode()

# get quote by providing message that should have not been encrypted
s = requests.Session()
s.get(server)
s.cookies.set("grade", cookie_value, domain="127.0.0.1", path="/")

resp = s.get(server + "quote")
print(f"Received quote:\n f{resp.text}")
