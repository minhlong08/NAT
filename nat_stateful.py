import socket
import time

from nat_models import IPv4Header, NatConfig, NatSockets, NatState, UdpHeader

def create_sockets(config: NatConfig) -> NatSockets:
    """
    Create internal and external socket for the NAT
    """
    internal_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    internal_sock.bind(("127.0.0.1", config.real_internal_port))

    external_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    external_sock.bind(("127.0.0.1", 0))

    return NatSockets(
        internal_sock=internal_sock,
        external_sock=external_sock,
    )

def allocate_nat_port(state: NatState, config: NatConfig) -> int | None:
    """
    Allocate a NAT port
    Return None if no more ports available
    """
    for port in range(1, config.num_external_ports + 1):
        if port not in state.external_to_internal:
            return port
    return None

def cleanup_expired_mappings(state: NatState, timeout: int) -> None:
    """ 
    Clean up expired mappings 
    """
    now = time.time()
    expired_keys = []

    for internal_key, entry in state.internal_to_external.items():
        if now - entry["last_used"] > timeout:
            expired_keys.append(internal_key)

    for internal_key in expired_keys:
        nat_port = state.internal_to_external[internal_key]["nat_port"]
        del state.internal_to_external[internal_key]
        del state.external_to_internal[nat_port]
        print("Expired mapping:", internal_key, "->", nat_port)


def get_or_create_mapping(
    internal_key: tuple[str, int],
    addr: tuple[str, int],
    src_ip: str,
    src_port: int,
    state: NatState,
    config: NatConfig,
) -> tuple[int | None, bool]:
    """
    Allocate a new mapping or return an old mapping if exists
    Return the nat port and a boolean value indicating if a new mapping was created
    """
    now = time.time()

    if internal_key in state.internal_to_external:
        nat_port = state.internal_to_external[internal_key]["nat_port"]
        state.internal_to_external[internal_key]["last_used"] = now
        state.internal_to_external[internal_key]["real_addr"] = addr

        state.external_to_internal[nat_port]["last_used"] = now
        state.external_to_internal[nat_port]["real_addr"] = addr

        print("Existing mapping:", internal_key, "->", nat_port)
        return nat_port, False

    nat_port = allocate_nat_port(state, config)
    if nat_port is None:
        return None, False

    state.internal_to_external[internal_key] = {
        "nat_port": nat_port,
        "last_used": now,
        "real_addr": addr,
    }

    state.external_to_internal[nat_port] = {
        "internal_ip": src_ip,
        "internal_port": src_port,
        "last_used": now,
        "real_addr": addr,
    }

    print("New mapping:", internal_key, "->", nat_port)
    return nat_port, True
