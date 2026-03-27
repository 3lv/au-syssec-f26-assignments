Simulate long download from the internet
```bash
curl -o /dev/null --limit-rate 100k http://ipv4.download.thinkbroadband.com/100MB.zip
```

Optionally, to get ip addr:
```bash
getent hosts ipv4.download.thinkbroadband.com
# 80.249.99.148
```
By default, this should take ~1000seconds ~ 17min


Note that by not sending the tcp options(TSval and TSecr) the server seem to ignore our packets.

Trying to get the previous TSval and TSecr from a real ACK packet, and resend it latter with RST+ACK (like if the client would have disconnected). Even without incrementing the TSval, the server seems to accept our RST+ACK packets and close the connection.

Currently, to not intercept our own packats, we are filtering for newer packets than some state we maintain, which is not robust but works
