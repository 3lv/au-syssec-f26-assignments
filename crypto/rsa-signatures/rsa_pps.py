import secrets
import sympy

import hashlib
# TODO: Implement my own sha256
def hash(m: bytes):
    return hashlib.sha256(m).digest()

def gen_prime(bits: int) -> int:
    """
    # Not so secure :)
    """
    while True:
        x = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        p = int(sympy.nextprime(x))
        if p.bit_length() == bits:
            return p

def generate_rsa_key(moduli_length_bits: int = 3072, e: int = 65537):
    while True:
        p = gen_prime(moduli_length_bits//2)
        q = gen_prime(moduli_length_bits//2)
        if p == q:
            continue

        n = p * q
        if n.bit_length() != moduli_length_bits:
            continue
            
        phi = (p - 1) * (q - 1)
        if sympy.gcd(e, phi) != 1:
            continue

        # TODO: Implement this myself
        d = pow(e, -1, phi)
        return (n, e, d)


def xor_blocks(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b), "Blocks must be the same size"
    return bytes([a ^ b for a, b in zip(a, b)])

def compare_blocks(a: bytes, b: bytes) -> bool:
    assert len(a) == len(b), "Blocks must be the same size"
    print("Debug: comparing blocks:")
    print(a)
    print(b)

    s = 0
    for a, b in zip(a, b):
        s += a ^ b

    if s == 0:
        return True
    else:
        return False

def pss_encoding(m: bytes, output_length: int):
    m_hash = hash(m)
    salt = secrets.token_bytes(32)
    salted_m_hash = hash(bytes([0]) * 8 + m_hash + salt) # Prepadd with zeros

    # Leave space for hash(32), salt(32), (0x01) and (0xbc)
    data_block = bytes([0]) * (output_length - 32 - 32 - 2) + \
        bytes([0x01]) + salt

    
    # Mask with length of data_block
    data_block_mask = MGF1(hash, 32, salted_m_hash, output_length - 32 - 1)
    masked_data_block = xor_blocks(data_block, data_block_mask)

    encoded_message = masked_data_block + salted_m_hash + bytes([0xbc])
    return encoded_message

def rsa_pss_sign(m: bytes, N: int, d: int, output_length=3072//8):
    encoded_m = pss_encoding(m, output_length)
    m = int.from_bytes(encoded_m, "big")
    sig = pow(m, d, N)
    return sig.to_bytes(output_length, "big")

def rsa_pss_verify(m: bytes, sig: bytes, N: int, e: int, output_length=3072//8):
    ok = True

    signed_encoded_message = int.from_bytes(sig, "big")
    encoded_message = pow(signed_encoded_message, e, N)
    encoded_message = encoded_message.to_bytes(output_length, "big")

    if encoded_message[-1] != 0xbc:
        print("encoded_message doesn't have 0xbc bytes")
        ok = False
    
    masked_data_block, salted_m_hash = encoded_message[:-33], encoded_message[-33:-1]
    data_block_mask = MGF1(hash, 32, salted_m_hash, output_length - 32 - 1)

    data_block = xor_blocks(masked_data_block, data_block_mask)
    padding_len = output_length - 32 - 32 - 2
    padding = bytes([0x00]) * padding_len + bytes([0x01])
    
    structure = compare_blocks(data_block[:padding_len+1], padding)

    if not structure:
        print("data_block doesn't follow structure")
        ok = False
    
    salt = data_block[padding_len+1:]
    expected_salted_m_hash = hash(bytes([0]) * 8 + hash(m) + salt)

    if expected_salted_m_hash != salted_m_hash:
        ok = False
    
    return ok

def MGF1(hash_fn, hash_len: int, seed: bytes, mask_length: int):
    n = (mask_length + hash_len - 1) // hash_len

    blocks = []
    for i in range(n):
        blocks.append(hash_fn(seed + i.to_bytes(4, "big")))
    
    mask = b"".join(blocks)
    return mask[0:mask_length]