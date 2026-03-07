 #include "crypto.h"

int aes_gcm_encrypt(
    const unsigned char *plaintext, int plaintext_len,
    const unsigned char *aad, int aad_len,
    const unsigned char *key,
    const unsigned char *iv, int iv_len,
    unsigned char *ciphertext,
    unsigned char *tag
) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto err;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1)
        goto err;

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto err;

    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1)
            goto err;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
        goto err;
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        goto err;
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
        goto err;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int aes_gcm_decrypt(
    const unsigned char *ciphertext, int ciphertext_len,
    const unsigned char *aad, int aad_len,
    const unsigned char *tag,
    const unsigned char *key,
    const unsigned char *iv, int iv_len,
    unsigned char *plaintext
) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto err;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1)
        goto err;

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto err;

    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1)
            goto err;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
        goto err;
    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1)
        goto err;

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        return -1; // authentication failed
    }

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}