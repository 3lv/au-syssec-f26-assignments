// Make header idempotent
#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>
#include <openssl/rand.h>

int aes_gcm_encrypt(
    const unsigned char *plaintext, int plaintext_len,
    const unsigned char *aad, int aad_len,
    const unsigned char *key,
    const unsigned char *iv, int iv_len,
    unsigned char *ciphertext,
    unsigned char *tag
);

int aes_gcm_decrypt(
    const unsigned char *ciphertext, int ciphertext_len,
    const unsigned char *aad, int aad_len,
    const unsigned char *tag,
    const unsigned char *key,
    const unsigned char *iv, int iv_len,
    unsigned char *plaintext
);

#endif // CRYPTO_H