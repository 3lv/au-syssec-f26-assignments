###

Inspect icmp packets:
```bash
sudo tcpdump -ni wlp1s0 -vvv -X icmp
```

Set up firewall to allow only icmp (Some might think this allows only ping, which is not true)
```bash
nft -f nft/icmp-only.nft
```
> Also check `nft/ping-only.nft` and `nft/allow-nothing.nft`

List active ruleset:
```bash
nft list ruleset
```

> Note: The following disables the firewall entirely, use with caution
Disable firewall:
```bash
nft flush ruleset
```



using aes-gcm-128 for message encryption

Generate key with
```bash
openssl rand -hex 16
```
Then hardcode it in the code