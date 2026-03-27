import sys
import socket
import struct
from Crypto.Cipher import AES

from env import (
    PORT
    ,SHARED_KEY
)


class IcmpPacketServer:
    def __init__(self, port=None, ttl=64, icmp_id=12345):
        self.port = port
        self.ttl = ttl
        self.icmp_id = icmp_id

    def decrypt(self, data, key):
        nonce = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        return cipher.decrypt_and_verify(ciphertext, tag)

    def receive_icmp_packet(self):
        # Create raw socket
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP) as sock:
            print("Created socket. Start listening.")

            sock.bind((socket.gethostbyname(socket.gethostname()), 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            try: 
                while True:
                    raw_packet, addr = sock.recvfrom(65535)

                    icmp_data = raw_packet[20:]
                    icmp_type = icmp_data[0] # ICMP type

                    if icmp_type != 47:
                        continue

                    payload = icmp_data[8:]
                    plaintext = self.decrypt(payload, SHARED_KEY)

                    print(f"Received plaintext: {plaintext.decode()}")
            finally:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


if __name__ == "__main__":
    print("Starting up ecc-server")
    icmp_packet_server = IcmpPacketServer(port=PORT)
    icmp_packet_server.receive_icmp_packet()