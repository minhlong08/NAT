# Stateful UDP Network Address Translator (NAT)

A robust, fully functional Network Address Translation (NAT) implementation written in Python. This project translates raw IPv4 and UDP packets between an internal network and an external network, maintaining stateful port mappings, handling packet fragmentation and reassembly, and dynamically issuing appropriate ICMP control messages.

## 🚀 Features

* **Stateful UDP Translation:** Dynamically allocates NAT ports for outbound traffic and maintains bidirectional mappings to seamlessly route returning external traffic.
* **IPv4 Fragmentation & Reassembly:** Fully supports MTU constraints by accurately fragmenting oversized outbound packets and securely buffering/reassembling inbound fragments.
* **Robust ICMP Error Handling:** Automatically generates and routes ICMP error messages (e.g., *Time Exceeded*, *Destination Unreachable*, *Fragmentation Needed and DF Set*) back to the original sender.
* **Strict Checksum Validation:** Recomputes and validates both IPv4 header checksums and UDP pseudo-header checksums to ensure data integrity across hops.
* **Automatic State Cleanup:** Actively monitors and expires stale translation mappings and incomplete reassembly buffers based on configurable timeout thresholds.
* **Asynchronous I/O:** Utilizes non-blocking multiplexing (`select`) to efficiently process concurrent inbound and outbound traffic streams.

---

## 🛠 Architecture & Module Breakdown

The project follows a clean, modular architecture, separating network logic, state management, and packet manipulation into distinct components:

| Module | Responsibilities |
| :--- | :--- |
| `nat.py` | The main entry point. Initializes sockets and runs the central event loop using `select` to handle asynchronous traffic and state cleanup. |
| `nat_args.py` | Validates and parses command-line arguments, instantiating the configuration state. |
| `nat_models.py` | Defines immutable data structures (`dataclasses`) representing IP headers, UDP headers, and the global NAT state. |
| `nat_packet.py` | Handles byte-level parsing, internet checksum calculation, and raw packet construction for IPv4 and UDP headers. |
| `nat_stateful.py` | Manages socket creation and the lifecycle of internal-to-external port mappings (allocation, retrieval, and expiration). |
| `nat_fragments.py` | Contains the logic for breaking packets down to fit MTU limits and safely reassembling incoming fragments using an identification buffer. |
| `nat_handlers.py` | Coordinates the core translation logic (modifying IPs/ports) for both inbound and outbound traffic flows. |
| `nat_icmp.py` | Generates standardized ICMP datagrams with proper payload quoting for network error reporting. |

---

## ⚙️ Installation & Requirements

This implementation relies strictly on Python standard libraries (`socket`, `struct`, `select`, `dataclasses`). No external dependencies or packages are required.

* **Requirement:** Python 3.10+ (for type hinting and modern dataclass support).

Clone the repository and ensure all files are in the same directory:
```bash
git clone <your-repository-url>
cd <your-repository-directory>

## 💻 Usage

To run the NAT, execute `nat.py` via the command line with the required network parameters. 

```bash
python3 nat.py <external_ip> <num_external_ports> <timeout> <mtu> <real_internal_port> <real_next_hop_port>
```

### Configuration Arguments

| Argument | Description | Validation Constraints |
| :--- | :--- | :--- |
| `external_ip` | The public IPv4 address the NAT will use to communicate with the external network. | Must be valid IPv4; cannot be within `10.0.0.0/8`. |
| `num_external_ports` | The maximum number of simultaneous external ports available for NAT mappings. | Integer: `1` to `65535` |
| `timeout` | Time (in seconds) before an idle mapping or incomplete fragmentation buffer is expired. | Integer: `> 0` |
| `mtu` | Maximum Transmission Unit. Packets larger than this will be fragmented (if DF flag allows). | Integer: `64` to `1024` |
| `real_internal_port` | The local port the NAT binds to for receiving traffic from the internal network. | Integer: `1` to `65535` |
| `real_next_hop_port` | The local port the NAT forwards external-bound traffic to (the external router/gateway). | Integer: `1` to `65535` |

### Example Run

```bash
python3 nat.py 203.0.113.5 100 30 500 8000 8001
```
*This command starts the NAT using `203.0.113.5` as its public IP, allocating up to 100 ports, with a 30-second timeout, a 500-byte MTU, listening for internal traffic on port 8000, and routing outbound traffic to port 8001.*