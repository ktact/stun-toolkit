import socket
import struct

# Constants
STUN_BINDING_METHOD = 0x0001
STUN_MAGIC_COOKIE   = 0x2112A442
XOR_MAPPED_ADDRESS  = 0x0020

# Set up UDP server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(("", 3478)) # Default STUN port

while True:
    data, addr = server_socket.recvfrom(1024)

    # Check if it's a STUN binding request
    if len(data) >= 20: # Minimum length for a STUN message
        header = struct.unpack(">HHI", data[0:8])
        method = header[0] & 0x3FFF
        magic_cookie = header[2]

        if method == STUN_BINDING_METHOD and magic_cookie == STUN_MAGIC_COOKIE:
            print(f"Received STUN binding request from {addr}")

            address = addr[0]
            port    = addr[1]

            # Create XOR-MAPPED-ADDRESS attribute
            address_family = 0x01
            xor_port = port ^ (STUN_MAGIC_COOKIE >> 16)
            xor_address = int.from_bytes(socket.inet_aton(address), 'big') ^ STUN_MAGIC_COOKIE
            xor_mapped_address = struct.pack(">HH2s4s",
                                             XOR_MAPPED_ADDRESS,
                                             0x0008,
                                             xor_port.to_bytes(2, 'big'),
                                             xor_address.to_bytes(4, 'big'))

            # Concatenate with the family field
            xor_mapped_address = struct.pack(">HB", 0x0020, 0x0008) + address_family.to_bytes(1, 'big') + xor_mapped_address

            # Create a response message
            response_message = struct.pack(">HHI12s", 0x0101, 0x0008, STUN_MAGIC_COOKIE, data[8:20]) + xor_mapped_address

            # Send the response to the client
            server_socket.sendto(response_message, addr)
        else:
            print(f"Ignoring non-binding request from {addr}")
