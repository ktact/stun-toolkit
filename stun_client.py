"""
This code sends a STUN (Session Traversal Utilities for NAT) request to a STUN server
to discover the public IP address and port that a NAT (Network Address Translation) has
allocated for the client. It then prints the discovered public IP address and port.

To use this code, ensure that the specified STUN server and port are reachable from your
network. The code is configured to use Google's public STUN server.

The code constructs a STUN binding request, sends it to the STUN server using UDP, and
receives a response containing the XOR-MAPPED-ADDRESS attribute. It then decodes this
attribute to obtain the public IP address and port.

This code can be used in contexts where you need to discover the public endpoint of a
client behind a NAT, such as in peer-to-peer networking or WebRTC applications.

Usage: python3 stun_client.py
"""

import socket
import struct
import os
import binascii

# STUN server IP and port
STUN_SERVER = "stun.l.google.com"
STUN_PORT   = 19302

# Message types
BINDING_REQUEST = 0x0001

# Attributes
MAPPED_ADDRESS     = 0x0001
XOR_MAPPED_ADDRESS = 0x0020

# Create a binding request with a random transaction ID
transaction_id = os.urandom(12)
stun_request = struct.pack("!HHI12s", BINDING_REQUEST, 0, 0x2112A442, transaction_id)

# Send the request to the STUN server
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(stun_request, (STUN_SERVER, STUN_PORT))

# Receive the response from the server
data, addr = sock.recvfrom(2048)

# Print the response in hex
print("Response in hex: ")
print(binascii.hexlify(data))

# Parse the header
msg_type, msg_length, magic_cookie, response_transaction_id = struct.unpack("!HHI12s", data[:20])

if msg_type != 0x0101 or transaction_id != response_transaction_id:
    print("Invalid STUN response")
    exit(1)

# Process the attributes
pos = 20
while pos < len(data):
    attr_type, attr_length = struct.unpack("!HH", data[pos:pos+4])

    if attr_type == 0x0020:  # XOR-MAPPED-ADDRESS
        # Skip the first byte after the attribute type and length
        pos += 1

        family, xor_port = struct.unpack("!BH", data[pos+4:pos+7])

        # XOR the port with the most significant 16 bits of the magic cookie
        port = xor_port ^ (0x2112A442 >> 16)
        # XOR the IP address with the magic cookie and transaction ID
        xor_address = struct.unpack("!I", data[pos+7:pos+11])[0]
        address = socket.inet_ntop(socket.AF_INET, struct.pack("!I", xor_address ^ 0x2112A442))
        print("Public IP address (XOR):", address)
        print("Public port (XOR):", port)

    pos += 4 + attr_length

sock.close()
