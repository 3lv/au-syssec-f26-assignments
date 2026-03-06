#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>

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

uint8_t* encrypt_message(const char* message, size_t message_size, const char* key, size_t key_size) {
    uint8_t *encrypted = (uint8_t *)malloc(message_size);
    for (size_t i = 0; i < message_size; i++) {
        encrypted[i] = message[i] ^ key[i % key_size];
    }
    return encrypted;
}

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

    size_t sml = 32;
    uint8_t *sm = (uint8_t *)malloc(sml * 1);
    while (1) {
        //Read from stdin
        printf("Enter a message to send: ");
        fgets((char *)sm, sml, stdin);
        uint8_t *ct = encrypt_message((char *)sm, sml, "mysecretkey", 11);
        //strcpy(sm, "Secret message");
        uint8_t *icmp = build_icmp_custom_format(47, 0, ct, sml);
        uint8_t icmpl = sml + 4*2;

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
            icmpl,                   // payload size
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
    }
    free(sm);

    libnet_destroy(l);
    return 0;
}