#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>
#include <libnet.h>

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

int main(int argc, char *argv[]) {
    // <source ip> <destination ip> <approach>
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <source ip> <destination ip> <approach>\n", argv[0]);
        return 1;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs failed: %s\n", errbuf);
        return 1;
    }
    pcap_t *handle = pcap_open_live("wlp1s0", 65535, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }
    // Capture packet with pcap:
    libnet_t *l = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if (!l) {
        fprintf(stderr, "libnet_init failed: %s\n", errbuf);
        return 1;
    }

    struct pcap_pkthdr *header;
    const uint8_t *data;
    int rc = pcap_next_ex(handle, &header, &data);
    int dlt = pcap_datalink(handle); // Probably ether
    uint32_t last_ack = 0;
    while (rc == 1) {
        // Find the l2 header length
        // get dlt type form handle
        uint8_t *ip = find_ip_start(data, header->len, dlt);
        if (!ip) {
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
        // Get the source ip from data
        char src_ip[16];
        snprintf(src_ip, sizeof(src_ip), "%d.%d.%d.%d", ip[12], ip[13], ip[14], ip[15]);
        char dst_ip[16];
        snprintf(dst_ip, sizeof(dst_ip), "%d.%d.%d.%d", ip[16], ip[17], ip[18], ip[19]);
        //printf("Captured packet from %s to %s\n", src_ip, dst_ip);
        if (strcmp(src_ip, argv[1]) == 0 && strcmp(dst_ip, argv[2]) == 0) {
            printf("Captured packet from %s to %s\n", src_ip, dst_ip);
            uint8_t *tcp = ip + ihl * 4;
            uint16_t src_port = (tcp[0] << 8) | tcp[1];
            uint16_t dst_port = (tcp[2] << 8) | tcp[3];
            printf("TCP flags: 0x%02x\n", tcp[13]);
            // Check if the ack flag is set, and only if (ack only is 0x10)
            /*
            if ((tcp[13] & 0x10) != 0 || (tcp[13] ^ 0x10) != 0) {
                rc = pcap_next_ex(handle, &header, &data);
                continue;
            }
            */
            uint32_t seq = (tcp[4] << 24) | (tcp[5] << 16) | (tcp[6] << 8) | tcp[7];
            uint32_t ack = (tcp[8] << 24) | (tcp[9] << 16) | (tcp[10] << 8) | tcp[11];
            printf("Ack number: %u\n", ack);
            if (ack <= last_ack) {
                // Already sent the packet for this ack, skip
                rc = pcap_next_ex(handle, &header, &data);
                continue;
            }
            last_ack = ack;
            // Get window
            uint16_t window = (tcp[14] << 8) | tcp[15];
            printf("Source port: %d, Destination port: %d\n", src_port, dst_port);
            uint32_t sip = libnet_name2addr4(l, src_ip, LIBNET_RESOLVE);
            uint32_t dip = libnet_name2addr4(l, dst_ip, LIBNET_RESOLVE);
            if (sip == (uint32_t)-1 || dip == (uint32_t)-1) {
                fprintf(stderr, "Invalid IP address\n");
                // Should not happen since we got it from the packet
                break;
            }
            // Recreate the same ACK packet that stats i still have to receive the bytes at ack
            libnet_ptag_t tcp_tag = libnet_build_tcp(
                /*
                dst_port,
                src_port,
                */
                src_port,
                dst_port,
                seq, //seq
                ack, //ack
                TH_ACK, // Control flags
                window, // window
                0, // checksum, autofill
                0, // urgent pointer
                0, // total length of tcp packet
                NULL, // payload
                0, // payload size
                l, // libnet context
                0 // 0 to build new one
            );
            if (tcp_tag == -1) {
                fprintf(stderr, "libnet_build_tcp failed: %s\n", libnet_geterror(l));
                break;
            }
            // Create ip header
            libnet_ptag_t ip_tag = libnet_build_ipv4(
                LIBNET_IPV4_H + LIBNET_TCP_H, // total length
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
                sip,
                dip,
                NULL, // payload
                0, // payload size
                l, // libnet context
                0 // 0 to build new one
            );
            if (ip_tag == -1) {
                fprintf(stderr, "libnet_build_ipv4 failed: %s\n", libnet_geterror(l));
                break;
            }
            // Send 3 more times:
            for (int i = 0; i < 3; i++) {
                int bytes = libnet_write(l);
                if (bytes == -1) {
                    fprintf(stderr, "libnet_write failed: %s\n", libnet_geterror(l));
                } else {
                    printf("Injected %d bytes(eth + ip + tcp)\n", bytes);
                }
            }
            libnet_clear_packet(l);
            //break; // Continue instead
        }
        rc = pcap_next_ex(handle, &header, &data);
    }

    libnet_destroy(l);
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}