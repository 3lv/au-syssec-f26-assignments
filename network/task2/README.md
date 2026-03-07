Simulate long download from the internet
```bash
curl -o /dev/null --limit-rate 100k http://ipv4.download.thinkbroadband.com/100MB.zip
```

Optionally, to get ip addr:
```bash
getent hosts ipv4.download.thinkbroadband.com
```
Should take ~1000seconds ~ 17min