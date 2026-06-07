import socket
from dataclasses import dataclass, field

ICMP_DEST_UNREACH = 3
ICMP_TIME_EXCEEDED = 11

ICMP_CODE_ADMIN_PROHIBITED = 13          # Communication Administratively Prohibited
ICMP_CODE_FRAG_NEEDED_DF_SET = 4         # Fragmentation Needed and DF Set
ICMP_CODE_TTL_EXPIRED = 0                # TTL Expired in Transit
ICMP_CODE_REASSEMBLY_EXCEEDED = 1        # Fragment Reassembly Time Exceeded


@dataclass
class NatConfig:
    external_ip: str
    num_external_ports: int
    timeout: int
    mtu: int
    real_internal_port: int
    real_next_hop_port: int


@dataclass
class NatSockets:
    internal_sock: socket.socket
    external_sock: socket.socket


@dataclass
class NatState:
    internal_to_external: dict = field(default_factory=dict)
    external_to_internal: dict = field(default_factory=dict)
    reassembly_buffer: dict = field(default_factory=dict)
    next_ip_id: int = 0


@dataclass
class IPv4Header:
    version: int
    ihl: int
    dscp: int
    ecn: int
    total_length: int
    identification: int
    flags: int
    frag_off: int
    ttl: int
    protocol: int
    checksum: int
    src_ip: str
    dst_ip: str


@dataclass
class UdpHeader:
    src_port: int
    dst_port: int
    udp_length: int
    udp_checksum: int


@dataclass
class UdpPacket:
    ip_header: IPv4Header
    udp_header: UdpHeader
    payload: bytes
