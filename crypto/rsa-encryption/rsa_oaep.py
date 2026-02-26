import secrets
import sympy

import hashlib

def bits_from_left_to_right(d: int, N: int):
    d = d % N
    n_bits = N.bit_length()
    bits = []
    for i in range(n_bits - 1, -1, -1):
        bits.append((d >> i) & 1)
    return bits

def secure_pow(c: int, d: int, N: int):
    r0 = 1
    r1 = c % N
    for bit in  bits_from_left_to_right(d, N):
        if bit == 1:
            r0 = (r0 * r1) % N
            r1 = (r1 * r1) % N
        else:
            r1 = (r0 * r1) % N
            r0 = (r0 * r0) % N
    return r0

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

    s = 0
    for a, b in zip(a, b):
        s += a ^ b

    if s == 0:
        return True
    else:
        return False

def partition(block: bytes, separator: int = 0x01):
    sep_index = len(block) // 2
    found = False

    for i in range(len(block)):
        if block[i] == separator and found == False:
            found = True
            sep_index = i
    
    if found:
        return (block[:sep_index], bytes([separator]), block[sep_index+1:])
    else:
        return (block[:sep_index], b'', block[sep_index+1:])

def oaep_encoding(message: bytes, label: bytes | None = None):
    """
    message: The message you want to encode
    label: Optional only authenticated label
    """
    assert len(message) <= 3072//8 - 2 * 32 - 2, "Message too long to encrypt"

    if label == None:
        label = bytes([0x00])

    label_hash = hash(label)
    padding_0_len = 3072//8 - len(message) - 2 * 32 - 2
    padding = bytes([0x00]) * padding_0_len + bytes([0x01])

    data_block = label_hash + padding + message

    seed = secrets.token_bytes(32)

    data_block_mask = MGF1(hash, 32, seed, len(data_block))
    masked_data_block = xor_blocks(data_block, data_block_mask)

    seed_mask = MGF1(hash, 32, masked_data_block, 32)
    masked_seed = xor_blocks(seed, seed_mask)

    encoded_message = bytes([0x00]) + masked_seed + masked_data_block
    return encoded_message

def rsa_oaep_encrypt(message: bytes, N: int, e: int, label: bytes | None = None, output_length=3072//8):
    encoded_message = oaep_encoding(message, label)
    encoded_message = int.from_bytes(encoded_message, "big")
    ciphertext = secure_pow(encoded_message, e, N)
    return ciphertext.to_bytes(output_length, "big")

def rsa_oaep_decrypt(ciphertext: bytes, N: int, d: int, label: bytes | None = None, output_length=3072//8):
    if label == None:
        label = bytes([0x00])
    
    ok = True # Is padding ok?

    ciphertext = int.from_bytes(ciphertext, "big")
    encoded_message = secure_pow(ciphertext, d, N)
    encoded_message = encoded_message.to_bytes(output_length, "big")

    if encoded_message[0] != 0x00:
        #print("encoded_message doesn't start with 0x00")
        ok = False
    
    masked_seed, masked_data_block = encoded_message[1:33], encoded_message[33:]
    seed_mask = MGF1(hash, 32, masked_data_block, 32)
    seed = xor_blocks(masked_seed, seed_mask)

    data_block_mask = MGF1(hash, 32, seed, len(masked_data_block))
    data_block = xor_blocks(masked_data_block, data_block_mask)

    label_hash, ps_byte_message = data_block[0:32], data_block[32:]
    
    #if label_hash != hash(label): # Not constant time
    if not compare_blocks(label_hash, hash(label)):
        #The ciphertext / label has been tampered with
        ok = False

    #ps, byte, message = ps_byte_message.partition(bytes([0x01])) # Not constant time
    ps, byte, message = partition(ps_byte_message, 0x01)
    if not byte: # Couldn't find 0x01 to split
        ok = False
    #if ps.strip(bytes([0x00])): # Something other than 0x00 in the first part
    if not compare_blocks(ps, bytes([0x00]) * len(ps)):
        ok = False

    if ok == False:
        message = None

    return message

def MGF1(hash_fn, hash_len: int, seed: bytes, mask_length: int):
    n = (mask_length + hash_len - 1) // hash_len

    blocks = []
    for i in range(n):
        blocks.append(hash_fn(seed + i.to_bytes(4, "big")))
    
    mask = b"".join(blocks)
    return mask[0:mask_length]