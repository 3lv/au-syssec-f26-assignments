#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"

static const unsigned char *KEY = (const unsigned char *)"e8da3236eb043efa91f9406cd8da0e1b";

uint16_t checksum(const void *icmp, size_t total_size) {
    const uint8_t *bytes = (const uint8_t *)icmp;
    uint32_t sum = 0;

    if (total_size % 2 == 0) {
        // Error coaie
        //return NULL;
    }
    
    for (size_t i = 0; i < total_size; i += 2) {
        uint16_t word = ((uint16_t)bytes[i] << 8) + bytes[i+1];
        sum += word;
    }

    // Ones complement
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

uint8_t* build_icmp_custom_format(uint8_t type, uint8_t code, const uint8_t* content, size_t content_size) {
    size_t total_size = 4*2 + content_size;
    uint8_t *icmp_payload = (uint8_t *)malloc((total_size));
    memset(icmp_payload, 0, total_size);
    memcpy(icmp_payload, &type, 1);
    memcpy(icmp_payload+1, &code, 1);
    memcpy(icmp_payload+4*2, content, content_size);
    uint16_t cs = checksum(icmp_payload, total_size);
    // Was in low endian by default
    uint8_t msb = (cs >> 8) & 0xFF;
    uint8_t lsb = cs & 0xFF;
    memcpy(icmp_payload+2, &msb, 1);
    memcpy(icmp_payload+3, &lsb, 1);
    return icmp_payload;
}

/*
uint8_t* encrypt_message(const char* message, size_t message_size, const char* key, size_t key_size) {
    uint8_t *encrypted = (uint8_t *)malloc(message_size);
    for (size_t i = 0; i < message_size; i++) {
        encrypted[i] = message[i] ^ key[i % key_size];
    }
    return encrypted;
}
*/


int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <destination IP>\n", argv[0]);
        return 1;
    }
    char errbuf[LIBNET_ERRBUF_SIZE];

    libnet_t *l = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if (!l) {
        fprintf(stderr, "libnet_init failed: %s\n", errbuf);
        return 1;
    }

    // When now on the same host, use src_ip 192.168.1.1
    uint32_t src_ip = libnet_name2addr4(l, "192.168.1.10", LIBNET_RESOLVE);
    uint32_t dst_ip = libnet_name2addr4(l, argv[1], LIBNET_RESOLVE);

    if (src_ip == (uint32_t)-1 || dst_ip == (uint32_t)-1) {
        fprintf(stderr, "Failed to resolve IP address\n");
        libnet_destroy(l);
        return 1;
    }

    size_t sml = 256;
    uint8_t *sm = (uint8_t *)malloc(sml);
    if (!sm) {
        fprintf(stderr, "Failed to allocate message buffer\n");
        libnet_destroy(l);
        return 1;
    }
    while (1) {
        //Read from stdin
        printf("Enter a message to send: ");
        if (!fgets((char *)sm, sml, stdin)) {
            break;
        }
        size_t msg_len = strnlen((char *)sm, sml);
        if (msg_len > 0 && sm[msg_len - 1] == '\n') {
            sm[msg_len - 1] = '\0';
            msg_len--;
        }
        if (msg_len == 0) {
            continue;
        }
        //uint8_t *ct = encrypt_message((char *)sm, sml, KEY, 32);
        uint8_t aad[16] = {0};
        uint8_t iv[12];
        if (RAND_bytes(iv, sizeof(iv)) != 1) {
            fprintf(stderr, "Failed to generate random IV\n");
            free(sm);
            libnet_destroy(l);
            return 1;
        }
        uint8_t tag[16];
        uint8_t *ct = malloc(msg_len);
        if (!ct) {
            fprintf(stderr, "Failed to allocate ciphertext buffer\n");
            break;
        }
        int ctl = aes_gcm_encrypt(sm, (int)msg_len, aad, sizeof(aad), KEY, iv, sizeof(iv), ct, tag);
        if (ctl < 0) {
            fprintf(stderr, "Encryption failed\n");
            free(ct);
            continue;
        }
        size_t full_ctl = 12 + (size_t)ctl + 16;
        uint8_t *full_ct = malloc(full_ctl);
        if (!full_ct) {
            fprintf(stderr, "Failed to allocate packet payload\n");
            free(ct);
            break;
        }
        memcpy(full_ct, iv, 12);
        memcpy(full_ct + 12, ct, (size_t)ctl);
        memcpy(full_ct + 12 + ctl, tag, 16);
        uint8_t *icmp = build_icmp_custom_format(47, 0, full_ct, full_ctl);
        free(full_ct);
        free(ct);
        if (!icmp) {
            fprintf(stderr, "Failed to build ICMP payload\n");
            break;
        }
        uint16_t icmpl = (uint16_t)(full_ctl + 4*2);

        libnet_ptag_t ip = libnet_build_ipv4(
            LIBNET_IPV4_H + icmpl,   // total length
            0,                   // TOS
            0x1234,              // ID
            0,                   // fragmentation
            64,                  // TTL
            //IPPROTO_RAW,         // protocol
            1, // Protocol ICMP
            0,                   // checksum, autofill
            src_ip,
            dst_ip,
            icmp,                // payload
            icmpl,                // payload size
            l,
            0
        );
        free(icmp);

        if (ip == -1) {
            fprintf(stderr, "libnet_build_ipv4 failed: %s\n", libnet_geterror(l));
            libnet_destroy(l);
            return 1;
        }

        int bytes = libnet_write(l);
        if (bytes == -1) {
            fprintf(stderr, "libnet_write failed: %s\n", libnet_geterror(l));
        } else {
            printf("Injected %d bytes\n", bytes);
        }
        libnet_clear_packet(l);
    }
    free(sm);

    libnet_destroy(l);
    return 0;
}
