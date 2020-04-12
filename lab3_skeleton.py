import socket
import struct


class Constants:
    MAX_RECEIVE = 65536
    MIN_IHL = 5
    UDP = 0x0011


class Formats(str):
    VER_IHL_FMT = '!B'
    NL_FMT = '!BHHHBBH4s4s'
    AL_FMT = '!HHLLB'
    AL_DATA_FMT = '!{}s'


class Index:
    IHL = 1


class Protocols(int):
    TCP = 6


class Terminal(str):
    ANSI_RESET = '\u001B[0m'
    ANSI_RED = '\u001B[31m'
    ANSI_GREEN = '\u001B[32m'


class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload


class TcpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """

    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    # Converts a byte-array IP address to a string
    # the input is on the form b'\xaa\xab'... a byte array
    return '.'.join(map(str, raw_ip_addr))


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section

    tcp_header = struct.unpack(Formats.AL_FMT, ip_packet_payload[:13])

    src_port = tcp_header[0]
    dst_port = tcp_header[1]
    data_offset = tcp_header[4] >> 4

    index = get_header_len(data_offset)
    payload = struct.unpack(Formats.AL_DATA_FMT.format(len(ip_packet_payload[index:])), ip_packet_payload[index:])[0]

    return TcpPacket(src_port, dst_port, data_offset, payload)


def get_def_tcp_packet() -> TcpPacket:
    return TcpPacket(-1, -1, -1, b'')


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section

    ihl = nl_parse_ihl(struct.unpack(Formats.VER_IHL_FMT, ip_packet[:Index.IHL]))
    if ihl == -1:
        return get_def_ip_packet()

    packet = struct.unpack(Formats.NL_FMT, ip_packet[Index.IHL:get_header_len(ihl)])

    protocol = nl_parse_protocol(packet)
    ip_src = nl_parse_ip_src(packet)
    ip_dst = nl_parse_ip_dst(packet)
    payload = nl_parse_payload(ip_packet, start=get_header_len(ihl), end=nl_parse_total_len(packet))

    return IpPacket(protocol, ihl, ip_src, ip_dst, payload)


def get_def_ip_packet() -> IpPacket:
    return IpPacket(-1, -1, "0.0.0.0", "0.0.0.0", b'')


def nl_parse_total_len(packet: tuple) -> int:
    return packet[1]


def nl_parse_ihl(packet: tuple) -> int:
    ihl = packet[0] & 0x0F
    if ihl < Constants.MIN_IHL:
        print(f'{Terminal.ANSI_RED}[ERROR] Expected IHL value greater than 4 '
              f'but got {ihl} instead.{Terminal.ANSI_RESET}')
        return -1
    return ihl


def nl_parse_protocol(packet):
    return packet[5]


def nl_parse_ip_src(packet: tuple):
    return parse_raw_ip_addr(packet[7])


def nl_parse_ip_dst(packet: tuple):
    return parse_raw_ip_addr(packet[8])


def nl_parse_payload(packet: bytes, start: int, end: int) -> bytes:
    payload = packet[start:end]
    return struct.unpack('!{}s'.format(len(payload)), payload)[0]


def get_header_len(offset: int) -> int:
    return offset * 4


def setup_sockets() -> socket:
    return socket.socket(socket.AF_INET, socket.SOCK_RAW, Constants.UDP)


def main():
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)

    # iface_name = "lo"
    # stealer.setsockopt(socket.SOL_SOCKET,
    #                    socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))
    stealer_socket = setup_sockets()
    try:
        while True:
            packet, addr = stealer_socket.recvfrom(Constants.MAX_RECEIVE)
            ip_packet: IpPacket = parse_network_layer_packet(packet)
            if ip_packet.protocol == Protocols.TCP:
                tcp_packet: TcpPacket = parse_application_layer_packet(ip_packet.payload)
                payload: bytes = tcp_packet.payload
                print(payload.decode('utf-8'))
    except KeyboardInterrupt:
        print(f'{Terminal.ANSI_RED}Program closed due to KeyboardInterrupt.{Terminal.ANSI_RESET}')
        exit(-1)


if __name__ == "__main__":
    main()
