#!/usr/bin/env python3

import fcntl
import struct
import os
import time
import socket
import ssl
import select

# Creating the TUN interface
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print(f"[*] TUN interface created with success: {ifname}")

os.system(f"ip addr add 10.4.2.99/24 dev {ifname}")
os.system(f"ip link set dev {ifname} up")

IP = '0.0.0.0'
PORT = 9090    # Port of the VPN

# Security context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('./certificate/server.crt', './certificate/server.key')
# Forcing authentication
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations('./certificate/ca.crt')

# Creating the connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((IP, PORT))
sock.listen(1)
print(f"[*] Waiting for the client to connect on port {PORT}...")

conn, addr = sock.accept()
ssock = context.wrap_socket(conn, server_side=True)
print(f"[*] Secure TLS connection with {addr}!")

while True:
    ready, _, _ = select.select([tun, ssock], [], [])

    for fd in ready:
        if fd is tun:
            # Send the data on the encrypted tunnel
            packet = os.read(tun, 2048)
            if packet:
                ssock.sendall(packet)
        
        elif fd is ssock:
            # Decrypt the data and send it on the network
            data = ssock.recv(2048)
            if data:
                os.write(tun, data)
            else:
                print("[!] The client has disconnected.")
                exit(0)