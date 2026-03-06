#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char errbuf[LIBNET_ERRBUF_SIZE];

    libnet_t *l = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if (!l) {
        fprintf(stderr, "libnet_init failed: %s\n", errbuf);
        return 1;
    }

    uint32_t src_ip = libnet_name2addr4(l, "192.168.1.10", LIBNET_RESOLVE);
    uint32_t dst_ip = libnet_name2addr4(l, "192.168.1.1", LIBNET_RESOLVE);

    if (src_ip == (uint32_t)-1 || dst_ip == (uint32_t)-1) {
        fprintf(stderr, "Failed to resolve IP address\n");
        libnet_destroy(l);
        return 1;
    }

    libnet_ptag_t ip = libnet_build_ipv4(
        LIBNET_IPV4_H + 0,   // total length
        0,                   // TOS
        0x1234,              // ID
        0,                   // fragmentation
        64,                  // TTL
        IPPROTO_RAW,         // protocol
        0,                   // checksum, autofill
        src_ip,
        dst_ip,
        NULL,                // payload
        0,                   // payload size
        l,
        0
    );

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

    libnet_destroy(l);
    return 0;
}