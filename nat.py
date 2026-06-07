import select
import sys

from nat_args import parse_args
from nat_fragments import cleanup_reassembly_timeouts, process_inbound_packet
from nat_handlers import handle_inbound_packet, handle_outbound_packet
from nat_models import NatState
from nat_packet import validate_packet
from nat_stateful import cleanup_expired_mappings, create_sockets


def main():
    config = parse_args()
    sockets = create_sockets(config)
    state = NatState()

    while True:
        cleanup_expired_mappings(state, config.timeout)
        cleanup_reassembly_timeouts(state, config.timeout, config, sockets)

        readable, _, _ = select.select(
            [sockets.internal_sock, sockets.external_sock],
            [],
            [],
            1.0,
        )

        for sock in readable:
            try:
                if sock is sockets.internal_sock:
                    data, addr = sockets.internal_sock.recvfrom(1024)
                    print("Received from internal:", addr)
                    udp_packet = validate_packet(data)
                    handle_outbound_packet(
                        udp_packet=udp_packet,
                        raw_packet=data,
                        addr=addr,
                        config=config,
                        state=state,
                        sockets=sockets,
                    )

                elif sock is sockets.external_sock:
                    data2, addr2 = sockets.external_sock.recvfrom(1024)
                    print("Received from external:", addr2)

                    # Check if the received packet need to be reassemble
                    result = process_inbound_packet(
                        data=data2,
                        recv_addr=addr2,
                        state=state,
                    )
                    if result is None:
                        continue

                    udp_packet, raw_packet = result

                    handle_inbound_packet(
                        udp_packet=udp_packet,
                        raw_packet=raw_packet,
                        recv_addr=addr2,
                        config=config,
                        state=state,
                        sockets=sockets,
                    )

            except ValueError as e:
                print("Dropped packet:", e, file=sys.stderr)


if __name__ == "__main__":
    main()
