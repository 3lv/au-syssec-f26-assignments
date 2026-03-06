#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

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

void display_data(const uint8_t *data, int size) {
    for (int i = 0; i < size; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

int main(void) {
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
    // find first icmpv4 and type 47
    while (rc == 1) {
        // Add the 14 for the Ethernet header and 9 to get to protocol in ip header
        // 20 is the ip header size
        if (header->len >= 34 && data[14 + 9] == 1 && data[14 + 20 + 0] == 47) {
            char *message = (char *)(data + 14 + 20 + 4*2);
            printf("Received message: %s\n", message);
        }
        rc = pcap_next_ex(handle, &header, &data);
    }

    if (rc == 0) {
        printf("Timeout waiting for packet\n");
    } else {
        fprintf(stderr, "pcap_next_ex failed: %s\n", pcap_geterr(handle));
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}