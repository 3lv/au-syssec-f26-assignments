import sys
import socket
import struct
from Crypto.Cipher import AES

from env import (
    PORT
    ,SHARED_KEY
)


class IcmpPacketSender:
    def __init__(self, port=None, ttl=64, icmp_id=12345):
        self.port = port
        self.ttl = ttl
        self.icmp_id = icmp_id

    def encrypt(self, data, key):
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        return cipher.nonce + tag + ciphertext

    def calculate_checksum(self, data):
        result = 0

        if len(data) % 2 != 0:
            data += b"\x00"
        
        for i in range(0, len(data), 2):
            result += (data[i] << 8) + data[i+1]

        result = (result >> 16) + (result & 0xffff) # fold carry
        result += result >> 16

        return (~result) & 0xffff

    def send_icmp_packet(self, data, target_ip):
        icmp_type = 47
        icmp_code = 0
        icmp_checksum = 0
        icmp_sequence = 1

        # Payload
        icmp_payload = data.encode()

        # Encrypt Payload
        enc_icmp_payload = self.encrypt(icmp_payload, SHARED_KEY)

        # ICMP header
        icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, self.icmp_id, icmp_sequence)

        # Calculate checksum
        icmp_checksum = self.calculate_checksum(icmp_header + enc_icmp_payload)

        # update header with calculated checksum
        icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, self.icmp_id, icmp_sequence)

        # ICMP packet
        icmp_packet = icmp_header + enc_icmp_payload

        # Create raw socket
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            # Set socket TTL
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack("I", self.ttl))
            sock.settimeout(20)

            sock.sendto(icmp_packet, (target_ip, self.port))

            print("Sent packet!")


if __name__ == "__main__":
    print("Starting up ecc-client")
    icmp_packet_sender = IcmpPacketSender(port=PORT)

    while True:
        data = input("Enter the message: ")
        target_ip = input("Enter the target IP: ")

        icmp_packet_sender.send_icmp_packet(data, target_ip)