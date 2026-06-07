import sys
import socket

from nat_models import NatConfig


def parse_args() -> NatConfig:
    """ 
    Parse command line arguments 
    Store the command line argument in NatConfig variable
    """
    if len(sys.argv) != 7:
        print("Usage: python3 nat.py <external_ip> <num_external_ports> <timeout> <mtu> <real_internal_port> <real_next_hop_port>", file=sys.stderr)
        sys.exit(1)

    external_ip = sys.argv[1]
    try:
        # validates IPv4 format
        socket.inet_aton(external_ip)
    except OSError:
        print("Invalid external_ip", file=sys.stderr)
        sys.exit(1)

    # external_ip must lie outside 10.0.0.0/8
    if external_ip.startswith("10."):
        print("external_ip must be outside 10.0.0.0/8", file=sys.stderr)
        sys.exit(1)

    try:
        num_external_ports = int(sys.argv[2])
        timeout = int(sys.argv[3])
        mtu = int(sys.argv[4])
        real_internal_port = int(sys.argv[5])
        real_next_hop_port = int(sys.argv[6])
    except ValueError:
        print("All numeric arguments must be integers", file=sys.stderr)
        sys.exit(1)

    if not (1 <= num_external_ports <= 65535):
        print("num_external_ports must be in range 1..65535", file=sys.stderr)
        sys.exit(1)

    if timeout <= 0:
        print("timeout must be > 0", file=sys.stderr)
        sys.exit(1)

    if not (64 <= mtu <= 1024):
        print("mtu must be in range 64..1024", file=sys.stderr)
        sys.exit(1)

    if not (1 <= real_internal_port <= 65535):
        print("real_internal_port must be in range 1..65535", file=sys.stderr)
        sys.exit(1)

    if not (1 <= real_next_hop_port <= 65535):
        print("real_next_hop_port must be in range 1..65535", file=sys.stderr)
        sys.exit(1)

    return NatConfig(
        external_ip=external_ip,
        num_external_ports=num_external_ports,
        timeout=timeout,
        mtu=mtu,
        real_internal_port=real_internal_port,
        real_next_hop_port=real_next_hop_port,
    )
