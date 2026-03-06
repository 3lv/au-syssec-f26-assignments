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
    const unsigned char *data;
    int rc = pcap_next_ex(handle, &header, &data);

    if (rc == 1) {
        printf("Captured packet of length %u bytes\n", header->len);
    } else if (rc == 0) {
        printf("Timeout waiting for packet\n");
    } else {
        fprintf(stderr, "pcap_next_ex failed: %s\n", pcap_geterr(handle));
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}