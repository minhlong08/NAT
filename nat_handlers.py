import struct
import time

from nat_fragments import fragment_ipv4_packet
from nat_icmp import send_icmp_error
from nat_models import (
    ICMP_CODE_ADMIN_PROHIBITED,
    ICMP_CODE_FRAG_NEEDED_DF_SET,
    ICMP_CODE_TTL_EXPIRED,
    ICMP_DEST_UNREACH,
    ICMP_TIME_EXCEEDED,
    IPv4Header,
    NatConfig,
    NatSockets,
    NatState,
    UdpHeader,
    UdpPacket,
)
from nat_packet import build_packet, extract_packet_fields
from nat_stateful import get_or_create_mapping


def handle_outbound_packet(
    udp_packet: UdpPacket,
    raw_packet: bytes,
    addr: tuple[str, int],
    config: NatConfig,
    state: NatState,
    sockets: NatSockets,
) -> None:
    """
    Forward internal packets to external network
    """
    ip_header = udp_packet.ip_header
    udp_header = udp_packet.udp_header
    payload = udp_packet.payload
    src_ip, dst_ip, src_port, dst_port = extract_packet_fields(ip_header, udp_header)

    # print("Before NAT:", src_ip, src_port, "->", dst_ip, dst_port)

    internal_key = (src_ip, src_port)
    nat_port, created_new = get_or_create_mapping(
        internal_key, addr, src_ip, src_port, state, config
    )

    if nat_port is None:
        send_icmp_error(
            offending_packet=raw_packet,
            recv_side="internal",
            real_dest_addr=addr,
            icmp_type=ICMP_DEST_UNREACH,
            icmp_code=ICMP_CODE_ADMIN_PROHIBITED,
            config=config,
            state=state,
            sockets=sockets,
        )
        return

    outgoing_packets, error_reason = translate_outbound_packet(
        ip_header=ip_header,
        udp_header=udp_header,
        payload=payload,
        new_src_ip=config.external_ip,
        new_dst_ip=dst_ip,
        new_src_port=nat_port,
        new_dst_port=dst_port,
        mtu=config.mtu,
    )

    if error_reason is not None:
        if created_new:
            del state.internal_to_external[internal_key]
            del state.external_to_internal[nat_port]

        if error_reason == "ttl_expired":
            send_icmp_error(
                offending_packet=raw_packet,
                recv_side="internal",
                real_dest_addr=addr,
                icmp_type=ICMP_TIME_EXCEEDED,
                icmp_code=ICMP_CODE_TTL_EXPIRED,
                config=config,
                state=state,
                sockets=sockets,
            )
            return

        if error_reason == "frag_needed_df":
            send_icmp_error(
                offending_packet=raw_packet,
                recv_side="internal",
                real_dest_addr=addr,
                icmp_type=ICMP_DEST_UNREACH,
                icmp_code=ICMP_CODE_FRAG_NEEDED_DF_SET,
                config=config,
                state=state,
                sockets=sockets,
                rest_of_header=struct.pack("!HH", 0, config.mtu),
            )
            return

    for i, packet in enumerate(outgoing_packets):
        print(
            f"Sending outbound packet/fragment {i + 1}: "
            f"{config.external_ip}:{nat_port} -> {dst_ip}:{dst_port}"
        )
        sockets.external_sock.sendto(packet, ("127.0.0.1", config.real_next_hop_port))



def translate_outbound_packet(
    ip_header: IPv4Header,
    udp_header: UdpHeader,
    payload: bytes,
    new_src_ip: str,
    new_dst_ip: str,
    new_src_port: int,
    new_dst_port: int,
    mtu: int,
) -> tuple[list[bytes] | None, str | None]:
    """
    Translate one outbound packet.

    Returns:
    - (list_of_packets, None) on success
    - (None, "ttl_expired") if forwarding would reduce TTL to 0
    - (None, "frag_needed_df") if packet exceeds MTU and DF is set
    """
    if ip_header.ttl <= 1:
        return None, "ttl_expired"

    translated_packet = build_packet(
        old_ip_header=ip_header,
        old_udp_header=udp_header,
        src_ip=new_src_ip,
        dst_ip=new_dst_ip,
        src_port=new_src_port,
        dst_port=new_dst_port,
        payload=payload,
    )

    if len(translated_packet) <= mtu:
        return [translated_packet], None

    if ip_header.flags & 0b010:
        return None, "frag_needed_df"

    return fragment_ipv4_packet(translated_packet, mtu), None



def handle_inbound_packet(
    udp_packet: UdpPacket,
    raw_packet: bytes,
    recv_addr: tuple[str, int],
    config: NatConfig,
    state: NatState,
    sockets: NatSockets,
) -> None:
    """
    Handle forwarding packets from external network back to the correct internal address
    """
    ip_header = udp_packet.ip_header
    udp_header = udp_packet.udp_header
    payload = udp_packet.payload
    src_ip, dst_ip, src_port, dst_port = extract_packet_fields(ip_header, udp_header)

    #print("Before reverse:", src_ip, src_port, "->", dst_ip, dst_port)

    if dst_ip != config.external_ip or dst_port not in state.external_to_internal:
        raise ValueError("No matching mapping for the incoming external packet")

    if ip_header.ttl <= 1:
        send_icmp_error(
            offending_packet=raw_packet,
            recv_side="external",
            real_dest_addr=recv_addr,
            icmp_type=ICMP_TIME_EXCEEDED,
            icmp_code=ICMP_CODE_TTL_EXPIRED,
            config=config,
            state=state,
            sockets=sockets,
        )
        return

    entry = state.external_to_internal[dst_port]
    now = time.time()
    entry["last_used"] = now

    internal_key = (entry["internal_ip"], entry["internal_port"])
    if internal_key in state.internal_to_external:
        state.internal_to_external[internal_key]["last_used"] = now

    new_dst_ip = entry["internal_ip"]
    new_dst_port = entry["internal_port"]
    real_internal_addr = entry["real_addr"]

    new_packet = build_packet(
        ip_header,
        udp_header,
        src_ip,
        new_dst_ip,
        src_port,
        new_dst_port,
        payload,
    )

    print("After reverse:", src_ip, src_port, "->", new_dst_ip, new_dst_port)
    sockets.internal_sock.sendto(new_packet, real_internal_addr)
