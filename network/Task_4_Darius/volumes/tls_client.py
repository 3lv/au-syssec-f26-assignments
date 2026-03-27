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
print(f"[*] TUN Interface created with success: {ifname}")

# Config IP address + add rute
os.system(f"ip addr add 10.4.2.5/24 dev {ifname}")
os.system(f"ip link set dev {ifname} up")
os.system(f"ip route add 192.168.60.0/24 dev {ifname}")

SERVER_IP = '10.9.0.11'
PORT = 9090

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
# Load the certificate
context.load_verify_locations('./certificate/ca.crt')
context.load_cert_chain('./certificate/client.crt', './certificate/client.key')

# Ignore hostname
context.check_hostname = False 

# Connect to server
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print(f"[*] Connect to {SERVER_IP} on port {PORT}...")
sock.connect((SERVER_IP, PORT))

ssock = context.wrap_socket(sock, server_hostname=SERVER_IP)
print(f"[*] Secure TLS connection with the server!")

while True:
    ready, _, _ = select.select([tun, ssock], [], [])

    for fd in ready:
        if fd is tun:
            packet = os.read(tun, 2048)
            if packet:
                ssock.sendall(packet)
        
        elif fd is ssock:
            data = ssock.recv(2048)
            if data:
                os.write(tun, data)
            else:
                print("[!] Connection with server interrupted.")
                exit(0)