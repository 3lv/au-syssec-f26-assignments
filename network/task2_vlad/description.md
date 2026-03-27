

For this task, we will solve it using the pcap and libnet libraries, which can listen/inject tcp packets, but cannot drop. Because of that, whenever we see some packet, we need to try to react as fast as possible, and usually try multiple times, as there will be race conditions (also, we don't have the edge, as we might be a little late to the party). The C libraries were a pain in the ass. First of all, we hardcoded the `wlp1s0` interface(sorry for wlan0 ppl). The kernel does a really nice thing for us, it transforms the wifi header into a ethernet one, which is usually a a set length, or at least easy to determine. We created the overkill function `find_ip_start_eth` which tries to determine the type (implemented just for eth), and then find the length of the eth header.
To inspect the tcp/ip, we looked in the wikipedia layout and checked the specific bytes manually.
- We filter packets which are not ipv4, by checking the version in the ip header.
- We also filter out non tcp packets (check the protocol to be value 6).
- We then extract the source ip and the dest ip from the tcp header and compare with our arguments, filter out if they don't match. 
Then we want to find a `seq` only flag in the tcp header which corresponds to 
tcp[13] == 0x10. 
Then we extract the `seq` and the `ack` numbers which we will use for our prediction.

Currently, to not intercept our own packats, we are filtering for newer packets than some state we maintain, which is not robust but works

Trying to send produce and send some dummy RST/ACK packets doesn't work. Inpsecting using tcpdump/wireshark shows that the tcp connection is using options, and in these options there are the TSval and TSecr, which are used by the server to determine if the packet is valid or not. By not sending these options, the server seem to ignore our packets. 

Now that we know that, we also extract the tsval and tsecr with a nice function we made called `parse_tcp_timestamps`. Watching carefully how these numbers usually increase in an honest connection, we can see that adding 100 to the tsval and keeping tsecr the same seems to be a fair guess. Now we are ready to prepare our packets:

We build the tcp options. Strangly putting just the 2 of the 4 bytes values for tsval and tsecr doesn't work, and we found out that we need to pad it with 2 NOP bytes to be a multiple of 4.

Then we build the tcp header. Because we want to send an ACK + RST, and it usually doesn't contain any data, the next seq + ack will be the same as the ones in the captured packet.

Building the ip header is straightforward as well, we keep almost everything like in the captured packet.

Finally we write the packet using libnet.
For the RST method we send only one (we found it surprisingly reliable), but can be changed in the code easily.

For the ACK aproach, we need to send 3 of them to trigger the server to close the connection.


For the testing we used:

Simulate long download from the internet
```bash
curl -o /dev/null --limit-rate 100k http://ipv4.download.thinkbroadband.com/100MB.zip
```

Optionally, to get ip addr:
```bash
getent hosts ipv4.download.thinkbroadband.com
# 80.249.99.148
```

And watched it in tcpdump/wireshark.
