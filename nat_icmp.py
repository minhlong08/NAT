import socket
import struct

from nat_models import NatConfig, NatSockets, NatState
from nat_packet import internet_checksum, parse_ip_header


def get_next_ip_id(state: NatState) -> int:
    """
    Return a unique IPv4 Identification value for a newly generated datagram.
    """
    ip_id = state.next_ip_id
    state.next_ip_id = (state.next_ip_id + 1) & 0xFFFF
    return ip_id



def build_icmp_error_payload(offending_packet: bytes) -> bytes:
    """
    Build the 28-byte quoted data for an ICMP error message:
    - original IPv4 header (20 bytes)
    - first 8 bytes of original IP payload

    If fewer than 28 bytes are available, pad with zeros.
    """
    if len(offending_packet) < 20:
        raise ValueError("Offending packet too short for quoted ICMP payload")

    ip_header = parse_ip_header(offending_packet[:20])
    total_len = min(ip_header.total_length, len(offending_packet))
    quote_len = min(total_len, 28)

    quoted = offending_packet[:quote_len]
    if len(quoted) < 28:
        quoted += b"\x00" * (28 - len(quoted))

    return quoted



def build_icmp_message(
    icmp_type: int,
    icmp_code: int,
    quoted_data: bytes,
    rest_of_header: bytes = b"\x00\x00\x00\x00",
) -> bytes:
    """
    Build one ICMP error message:
    - 8-byte ICMP header
    - 28-byte quoted data
    """
    if len(rest_of_header) != 4:
        raise ValueError("ICMP rest_of_header must be exactly 4 bytes")

    icmp_wo_checksum = struct.pack(
        "!BBH4s",
        icmp_type,
        icmp_code,
        0,
        rest_of_header,
    ) + quoted_data

    checksum = internet_checksum(icmp_wo_checksum)

    icmp_packet = struct.pack(
        "!BBH4s",
        icmp_type,
        icmp_code,
        checksum,
        rest_of_header,
    ) + quoted_data

    return icmp_packet



def build_ipv4_icmp_datagram(
    src_ip: str,
    dst_ip: str,
    icmp_payload: bytes,
    ip_id: int,
    ttl: int = 64,
) -> bytes:
    """
    Build an IPv4 datagram carrying an ICMP payload.
    """
    version = 4
    ihl = 5
    dscp = 0
    ecn = 0
    protocol = 1  # ICMP
    flags = 0
    frag_off = 0

    version_ihl = (version << 4) | ihl
    dscp_ecn = (dscp << 2) | ecn
    total_length = 20 + len(icmp_payload)
    flags_fragment_offset = (flags << 13) | frag_off

    src_ip_bytes = socket.inet_aton(src_ip)
    dst_ip_bytes = socket.inet_aton(dst_ip)

    ip_header_wo_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        dscp_ecn,
        total_length,
        ip_id,
        flags_fragment_offset,
        ttl,
        protocol,
        0,
        src_ip_bytes,
        dst_ip_bytes,
    )

    checksum = internet_checksum(ip_header_wo_checksum)

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        dscp_ecn,
        total_length,
        ip_id,
        flags_fragment_offset,
        ttl,
        protocol,
        checksum,
        src_ip_bytes,
        dst_ip_bytes,
    )

    return ip_header + icmp_payload



def send_icmp_error(
    offending_packet: bytes,
    recv_side: str,
    real_dest_addr: tuple[str, int],
    icmp_type: int,
    icmp_code: int,
    config: NatConfig,
    state: NatState,
    sockets: NatSockets,
    rest_of_header: bytes = b"\x00\x00\x00\x00",
) -> None:
    """
    Generate and send an ICMP error back toward the original sender using
    the same interface on which the offending packet was received.

    recv_side:
    - "internal": send via sockets.internal_sock
    - "external": send via sockets.external_sock
    """
    if len(offending_packet) < 20:
        return

    offending_ip_header = parse_ip_header(offending_packet[:20])

    quoted_data = build_icmp_error_payload(offending_packet)
    icmp_payload = build_icmp_message(
        icmp_type=icmp_type,
        icmp_code=icmp_code,
        quoted_data=quoted_data,
        rest_of_header=rest_of_header,
    )

    icmp_datagram = build_ipv4_icmp_datagram(
        src_ip=config.external_ip,
        dst_ip=offending_ip_header.src_ip,
        icmp_payload=icmp_payload,
        ip_id=get_next_ip_id(state),
        ttl=64,
    )

    if recv_side == "internal":
        print("Send ICMP packets")
        sockets.internal_sock.sendto(icmp_datagram, real_dest_addr)
    elif recv_side == "external":
        print("Send ICMP packets")
        sockets.external_sock.sendto(icmp_datagram, real_dest_addr)
    else:
        raise ValueError("recv_side must be 'internal' or 'external'")
