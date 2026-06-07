import socket
import struct
import time

from nat_models import IPv4Header, NatConfig, NatSockets, NatState, UdpPacket
from nat_packet import (
    build_packet,
    internet_checksum,
    parse_ip_header,
    validate_ipv4_checksum,
    validate_packet,
)


def fragment_ipv4_packet(packet: bytes, mtu: int) -> list[bytes]:
    """
    Fragment an IP packet to fit the MTU
    Return a list of packets
    """
    if len(packet) < 20:
        raise ValueError("Packet too short for IPv4 fragmentation")

    ip_header = parse_ip_header(packet[:20])
    ip_header_len = ip_header.ihl * 4

    if mtu < ip_header_len:
        raise ValueError("MTU too small for IPv4 header")

    # raw IPv4 payload
    ip_payload = packet[ip_header_len:ip_header.total_length]

    # Maximum payload that can fit in one fragment
    max_payload_per_fragment = mtu - ip_header_len

    # Every fragment except the last must have a payload length
    # that is a multiple of 8 bytes.
    non_last_payload_size = (max_payload_per_fragment // 8) * 8

    if non_last_payload_size == 0:
        raise ValueError("MTU too small to create fragments")

    fragments = []
    offset_bytes = 0
    total_payload_len = len(ip_payload)

    while offset_bytes < total_payload_len:
        remaining = total_payload_len - offset_bytes

        # Check if this should be the last fragments
        if remaining > max_payload_per_fragment:
            chunk_size = non_last_payload_size
            more_fragments = True
        else:
            chunk_size = remaining
            more_fragments = False

        fragment_payload = ip_payload[offset_bytes:offset_bytes + chunk_size]

        fragment = build_ipv4_fragment(
            base_ip_header=ip_header,
            fragment_payload=fragment_payload,
            frag_offset_bytes=offset_bytes,
            more_fragments=more_fragments,
        )

        fragments.append(fragment)
        offset_bytes += chunk_size

    return fragments



def build_ipv4_fragment(
    base_ip_header: IPv4Header,
    fragment_payload: bytes,
    frag_offset_bytes: int,
    more_fragments: bool,
) -> bytes:
    """ Build one IPv4 fragment """
    if frag_offset_bytes % 8 != 0:
        raise ValueError("Fragment offset must be a multiple of 8 bytes")

    version_ihl = (base_ip_header.version << 4) | (base_ip_header.ihl & 0x0F)
    dscp_ecn = (base_ip_header.dscp << 2) | (base_ip_header.ecn & 0x03)

    total_length = (base_ip_header.ihl * 4) + len(fragment_payload)

    flags = base_ip_header.flags & 0x06
    if more_fragments:  # if there is more fragment set the MF flag
        flags |= 0x01

    frag_offset_units = frag_offset_bytes // 8
    flags_fragment_offset = (flags << 13) | frag_offset_units

    src_ip_bytes = socket.inet_aton(base_ip_header.src_ip)
    dst_ip_bytes = socket.inet_aton(base_ip_header.dst_ip)

    ip_header_wo_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        dscp_ecn,
        total_length,
        base_ip_header.identification,
        flags_fragment_offset,
        base_ip_header.ttl,
        base_ip_header.protocol,
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
        base_ip_header.identification,
        flags_fragment_offset,
        base_ip_header.ttl,
        base_ip_header.protocol,
        checksum,
        src_ip_bytes,
        dst_ip_bytes,
    )

    return ip_header + fragment_payload



def is_fragmented_packet(ip_header: IPv4Header) -> bool:
    """
    Return True if the IPv4 packet is fragmented or is a fragment.
    """
    mf_set = (ip_header.flags & 0x01) != 0
    return mf_set or ip_header.frag_off != 0



def parse_ip_fragment(data: bytes) -> tuple[IPv4Header, bytes]:
    """
    Parse one IPv4 packet/fragment and return:
    - IPv4 header
    - raw IP payload (everything after the IP header)
    """
    if len(data) < 20:
        raise ValueError("Packet too short for IPv4 header")

    ip_header = parse_ip_header(data[:20])
    ip_header_len = ip_header.ihl * 4

    if len(data) < ip_header_len:
        raise ValueError("Packet too short for full IPv4 header")

    if ip_header.total_length > len(data):
        raise ValueError("Truncated IPv4 packet")

    if ip_header.total_length < ip_header_len:
        raise ValueError("IPv4 total length too small")

    ip_payload = data[ip_header_len:ip_header.total_length]
    return ip_header, ip_payload



def process_inbound_packet(
    data: bytes,
    recv_addr: tuple[str, int],
    state: NatState,
) -> tuple[UdpPacket, bytes] | None:
    """
    Process one inbound packet.

    Returns:
    - (udp_packet, raw_packet_bytes) when a complete inbound datagram is ready
    - None if the packet should be dropped or reassembly is still incomplete
    """
    ip_header, ip_payload = parse_ip_fragment(data)
    data = data[:ip_header.total_length]

    if ip_header.version != 4 or ip_header.ihl != 5 or ip_header.dscp != 0 or ip_header.ecn != 0:
        return None

    if ip_header.protocol != 17:
        return None

    if not validate_ipv4_checksum(data, ip_header):
        return None

    if not is_fragmented_packet(ip_header):
        try:
            udp_packet = validate_packet(data)
            return udp_packet, data
        except ValueError:
            return None

    reassembled_data = add_fragment_and_try_reassemble(
        ip_header=ip_header,
        ip_payload=ip_payload,
        raw_fragment=data,
        recv_addr=recv_addr,
        state=state,
    )
    if reassembled_data is None:
        return None

    try:
        udp_packet = validate_packet(reassembled_data)
        return udp_packet, reassembled_data
    except ValueError:
        return None



def add_fragment_and_try_reassemble(
    ip_header: IPv4Header,
    ip_payload: bytes,
    raw_fragment: bytes,
    recv_addr: tuple[str, int],
    state: NatState,
) -> bytes | None:
    """
    Reassemble the fragments
    """
    ident = ip_header.identification
    now = time.time()

    if ident not in state.reassembly_buffer:
        state.reassembly_buffer[ident] = {
            "header0": None,
            "fragments": {},
            "total_payload_length": None,
            "last_used": now,
            "recv_addr": recv_addr,
            "quote_source": None,   # use for sending ICMP message if needed
        }

    entry = state.reassembly_buffer[ident]
    entry["last_used"] = now
    entry["recv_addr"] = recv_addr

    offset_bytes = ip_header.frag_off * 8
    entry["fragments"][offset_bytes] = ip_payload

    # Prefer fragment 0 for ICMP quoting if available
    if ip_header.frag_off == 0:
        entry["header0"] = ip_header
        entry["quote_source"] = raw_fragment[:min(len(raw_fragment), 28)]

    # If this is the last fragment, we now know total IP payload length
    mf_set = (ip_header.flags & 0x01) != 0
    if not mf_set:
        entry["total_payload_length"] = offset_bytes + len(ip_payload)

    if entry["header0"] is None or entry["total_payload_length"] is None:
        return None

    total_payload_length = entry["total_payload_length"]
    fragments = entry["fragments"]

    assembled = bytearray()
    current = 0

    while current < total_payload_length:
        if current not in fragments:
            return None

        chunk = fragments[current]
        assembled.extend(chunk)
        current += len(chunk)

    header0 = entry["header0"]
    reassembled_packet = build_reassembled_packet(header0, bytes(assembled))

    del state.reassembly_buffer[ident]
    return reassembled_packet



def build_reassembled_packet(
    header0: IPv4Header,
    full_ip_payload: bytes,
) -> bytes:
    version_ihl = (header0.version << 4) | (header0.ihl & 0x0F)
    dscp_ecn = (header0.dscp << 2) | (header0.ecn & 0x03)

    total_length = (header0.ihl * 4) + len(full_ip_payload)

    # Reassembled datagram is no longer fragmented
    flags = header0.flags & 0x06   # keep reserved + DF, clear MF
    flags_fragment_offset = (flags << 13) | 0

    src_ip_bytes = socket.inet_aton(header0.src_ip)
    dst_ip_bytes = socket.inet_aton(header0.dst_ip)

    ip_header_wo_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        dscp_ecn,
        total_length,
        header0.identification,
        flags_fragment_offset,
        header0.ttl,
        header0.protocol,
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
        header0.identification,
        flags_fragment_offset,
        header0.ttl,
        header0.protocol,
        checksum,
        src_ip_bytes,
        dst_ip_bytes,
    )

    return ip_header + full_ip_payload



def cleanup_reassembly_timeouts(
    state: NatState,
    timeout: int,
    config: NatConfig,
    sockets: NatSockets,
) -> None:
    now = time.time()
    expired = []

    for ident, entry in state.reassembly_buffer.items():
        if now - entry["last_used"] > timeout:
            expired.append((ident, entry))

    for ident, entry in expired:
        header0 = entry.get("header0")
        quote_source = entry.get("quote_source")
        recv_addr = entry.get("recv_addr")

        # For timeout fragment packet, only send the ICMP message if the fragment number 0
        # which contian the IP header and UDP header is received
        if header0 is not None and quote_source is not None and recv_addr is not None:
            try:
                from nat_icmp import send_icmp_error
                from nat_models import ICMP_CODE_REASSEMBLY_EXCEEDED, ICMP_TIME_EXCEEDED

                send_icmp_error(
                    offending_packet=quote_source,
                    recv_side="external",
                    real_dest_addr=recv_addr,
                    icmp_type=ICMP_TIME_EXCEEDED,
                    icmp_code=ICMP_CODE_REASSEMBLY_EXCEEDED,
                    config=config,
                    state=state,
                    sockets=sockets,
                )
            except Exception:
                pass

        del state.reassembly_buffer[ident]
