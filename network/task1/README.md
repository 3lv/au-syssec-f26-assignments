# Task 1 (tricky icmp)


## Quick start:
```bash
make && sudo ./client 192.168.1.1 # Run the client
make && sudo ./server
```
>Start to type and send messages

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

## Details:

Sending via icmp type 47 code 0

Using aes-gcm-128 for message encryption
icmp content: iv+ct+tag

aad[16] = {0}  // I.e not really used

Generated key with
```bash
openssl rand -hex 16
```
Then hardcoded it in the code(fine due to the task description)