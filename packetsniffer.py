import socket
import struct
import textwrap


def main():
    # Create raw socket
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

    # Bind to local IP
    host = socket.gethostbyname(socket.gethostname())
    conn.bind((host, 0))

    # Include IP headers
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Enable promiscuous mode (Windows)
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print("Sniffer started... Press Ctrl+C to stop.\n")

    try:
        while True:
            raw_data, addr = conn.recvfrom(65535)
            ip_header = raw_data[0:20]

            # Unpack IP header
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = (version_ihl & 0xF) * 4

            ttl = iph[5]
            protocol = iph[6]
            src = socket.inet_ntoa(iph[8])
            target = socket.inet_ntoa(iph[9])

            print("\n" + "="*50)
            print(f"Version: {version} | TTL: {ttl}")
            print(f"Protocol: {protocol}")
            print(f"Source IP: {src}")
            print(f"Destination IP: {target}")

            payload = raw_data[ihl:]
            print("Payload:")
            print(format_payload(payload))

    except KeyboardInterrupt:
        print("\nStopping sniffer...")
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


def format_payload(data):
    width = 80
    return '\n'.join(textwrap.wrap(data.hex(), width))


if __name__ == "__main__":
    main()
