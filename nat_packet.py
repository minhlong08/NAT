import socket
import struct

from nat_models import IPv4Header, UdpHeader, UdpPacket


def parse_ip_header(data: bytes) -> IPv4Header:
    """ Parse IP header from a packet """
    (
        version_ihl,
        dscp_ecn,
        total_length,
        identification,
        flags_frag,
        ttl,
        protocol,
        checksum,
        src_ip_byte,
        dst_ip_byte,
    ) = struct.unpack("!BBHHHBBH4s4s", data)

    # unpack version + ihl
    version = version_ihl >> 4
    ihl = version_ihl & 0x0F

    # unpack dscp + ecn
    dscp = dscp_ecn >> 2
    ecn = dscp_ecn & 0x03

    # unpack flags + fragment offset
    flags = flags_frag >> 13
    frag_off = flags_frag & 0x1FFF

    # convert ip address to string form
    src_ip = socket.inet_ntoa(src_ip_byte)
    dst_ip = socket.inet_ntoa(dst_ip_byte)

    return IPv4Header(
        version=version,
        ihl=ihl,
        dscp=dscp,
        ecn=ecn,
        total_length=total_length,
        identification=identification,
        flags=flags,
        frag_off=frag_off,
        ttl=ttl,
        protocol=protocol,
        checksum=checksum,
        src_ip=src_ip,
        dst_ip=dst_ip,
    )


def parse_udp_header(data: bytes) -> UdpHeader:
    """ Parse UDP header from a packet"""
    src_port, dst_port, udp_length, udp_checksum = struct.unpack("!HHHH", data)
    return UdpHeader(
        src_port,
        dst_port,
        udp_length,
        udp_checksum,
    )


def parse_payload(data: bytes, ip_header: IPv4Header) -> bytes:
    """ Parse the payload (data) of a packet"""
    ip_header_len = ip_header.ihl * 4
    return data[ip_header_len + 8 : ip_header.total_length]

def extract_packet_fields(ip_header: IPv4Header, udp_header: UdpHeader) -> tuple[str, str, int, int]:
    """
    Helper function extracting the source, destination ip addresses and ports from the packet header
    """
    return (
        ip_header.src_ip,
        ip_header.dst_ip,
        udp_header.src_port,
        udp_header.dst_port,
    )

def parse_packet(data: bytes) -> tuple[IPv4Header, UdpHeader, bytes]:
    """ 
    Parse a complete packet
    Return ip header, udp header, payload 
    """
    if len(data) < 28:
        raise ValueError("Packet too short to be IPv4 + UDP")

    ip_header = parse_ip_header(data[:20])
    ip_header_len = ip_header.ihl * 4
    if len(data) < ip_header_len + 8:
        raise ValueError("Packet too short for UDP header")

    udp_header = parse_udp_header(data[ip_header_len:ip_header_len + 8])
    payload = parse_payload(data, ip_header)

    return (ip_header, udp_header, payload)



def internet_checksum(data: bytes) -> int:
    """Calculate the internet checksum"""
    # pad if odd length
    if len(data) % 2 == 1:
        data += b'\x00'

    checksum = 0

    # process 16-bit words
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word

        # wrap around carry
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # final 1's complement
    return ~checksum & 0xFFFF



def build_packet(
    old_ip_header: IPv4Header,
    old_udp_header: UdpHeader,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
) -> bytes:
    """
    Build a UDP packet with recomputed IPv4 and UDP checksums.
    """
    udp_length = 8 + len(payload)
    total_length = 20 + udp_length

    # ----- IPv4 header -----
    version_ihl = (old_ip_header.version << 4) | (old_ip_header.ihl & 0x0F)
    dscp_ecn = (old_ip_header.dscp << 2) | (old_ip_header.ecn & 0x03)
    flags_fragment_offset = (old_ip_header.flags << 13) | (old_ip_header.frag_off & 0x1FFF)

    src_ip_bytes = socket.inet_aton(src_ip)
    dst_ip_bytes = socket.inet_aton(dst_ip)

    ip_header_wo_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        dscp_ecn,
        total_length,
        old_ip_header.identification,
        flags_fragment_offset,
        old_ip_header.ttl - 1,
        old_ip_header.protocol,
        0,
        src_ip_bytes,
        dst_ip_bytes,
    )

    ip_checksum = internet_checksum(ip_header_wo_checksum)

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        dscp_ecn,
        total_length,
        old_ip_header.identification,
        flags_fragment_offset,
        old_ip_header.ttl - 1,
        old_ip_header.protocol,
        ip_checksum,
        src_ip_bytes,
        dst_ip_bytes,
    )

    # ----- UDP header -----
    udp_header_wo_checksum = struct.pack(
        "!HHHH",
        src_port,
        dst_port,
        udp_length,
        0,
    )

    pseudo_header = struct.pack(
        "!4s4sBBH",
        src_ip_bytes,
        dst_ip_bytes,
        0,
        old_ip_header.protocol,
        udp_length,
    )

    udp_checksum = internet_checksum(pseudo_header + udp_header_wo_checksum + payload)
    if udp_checksum == 0x0000:
        udp_checksum = 0xFFFF

    udp_header = struct.pack(
        "!HHHH",
        src_port,
        dst_port,
        udp_length,
        udp_checksum,
    )

    return ip_header + udp_header + payload



def validate_ipv4_checksum(data: bytes, ip_header: IPv4Header) -> bool:
    """
    Validate an packet's IP header checksum
    """
    header_len = ip_header.ihl * 4
    ip_header_bytes = data[:header_len]
    return internet_checksum(ip_header_bytes) == 0



def validate_udp_checksum(ip_header: IPv4Header, udp_header: UdpHeader, payload: bytes) -> bool:
    """
    Validate a packet's udp checksum
    """
    if udp_header.udp_checksum == 0:
        return True

    udp_length = udp_header.udp_length

    pseudo_header = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(ip_header.src_ip),
        socket.inet_aton(ip_header.dst_ip),
        0,
        ip_header.protocol,
        udp_length,
    )

    udp_header_bytes = struct.pack(
        "!HHHH",
        udp_header.src_port,
        udp_header.dst_port,
        udp_header.udp_length,
        udp_header.udp_checksum,
    )

    udp_segment = (udp_header_bytes + payload)[:udp_length]
    return internet_checksum(pseudo_header + udp_segment) == 0



def validate_packet(data: bytes) -> UdpPacket:
    """
    Given raw bytes, validate IPv4 + UDP structure and checksums.
    Return the parsed packet if valid, else raise ValueError.
    """
    ip_header, udp_header, payload = parse_packet(data)
    data = data[:ip_header.total_length]
    payload = data[ip_header.ihl * 4 + 8 : ip_header.total_length]

    if ip_header.version != 4 or ip_header.ihl != 5 or ip_header.dscp != 0 or ip_header.ecn != 0:
        raise ValueError("Incorrect IP header format")

    if ip_header.protocol != 17:
        raise ValueError("Incorrect protocol: only UDP is accepted here")

    if ip_header.total_length > len(data):
        raise ValueError("Truncated IPv4 packet")

    if ip_header.total_length < ip_header.ihl * 4 + 8:
        raise ValueError("IPv4 total length too small")

    udp_packet = UdpPacket(
        ip_header=ip_header,
        udp_header=udp_header,
        payload=payload,
    )

    if not validate_ipv4_checksum(data, ip_header):
        raise ValueError("Invalid IPv4 checksum")

    if not validate_udp_checksum(ip_header, udp_header, payload):
        raise ValueError("Invalid UDP checksum")

    return udp_packet
