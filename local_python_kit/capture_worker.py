#!/usr/bin/env python3
"""
ARX-PacketGuard Separate Live Capture Worker (Pyshark / TShark)
===============================================================
Runs outside the web request thread using a bounded ring buffer (maxlen=2048).
Captures packet metadata ONLY (never decrypts ARX payloads) and forwards batches
to the PacketGuard monitor API.

Platform-Specific Non-Root Setup:
- macOS: Install Wireshark (`brew install --cask wireshark`) which installs the
  `access_bpf` launch daemon (`ChmodBPF`) so your normal user can read `lo0` without `sudo`.
- Linux (Ubuntu/Debian):
  `sudo apt install tshark && sudo dpkg-reconfigure wireshark-common`
  `sudo usermod -aG wireshark $USER && sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap`
- Windows: Install Wireshark with Npcap ("Support loopback traffic" checked) and
  restrict Npcap only if required; run worker as standard user.
"""

import argparse
import collections
import shutil
import sys
import time
import requests


def verify_tshark_environment(interface: str) -> tuple[bool, str]:
    tshark_bin = shutil.which("tshark")
    if not tshark_bin:
        return (
            False,
            "TShark binary not found in PATH. Install Wireshark/TShark or use Recorded Demo Mode in the web UI.",
        )
    return True, f"Found TShark at {tshark_bin}"


def run_live_capture(interface: str, bpf_filter: str, api_url: str, max_buffer: int = 2048) -> None:
    ok, msg = verify_tshark_environment(interface)
    if not ok:
        print(f"[PacketGuard Worker Fallback] {msg}", file=sys.stderr)
        sys.exit(1)

    try:
        import pyshark  # type: ignore
    except ImportError:
        print(
            "[PacketGuard Worker Fallback] pyshark is not installed. Run `pip install -r requirements.txt`.",
            file=sys.stderr,
        )
        sys.exit(1)

    bounded_queue: collections.deque[dict] = collections.deque(maxlen=max_buffer)
    dropped_packets = 0

    print(f"[PacketGuard Worker] Starting live capture on interface='{interface}' filter='{bpf_filter}'")
    print(f"[PacketGuard Worker] Bounded queue capacity={max_buffer}. Streaming to {api_url}")

    try:
        capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter)
        last_flush = time.time()

        for idx, pkt in enumerate(capture.sniff_continuously()):
            ts_ms = int(float(pkt.sniff_timestamp) * 1000)
            protocol = pkt.highest_layer if hasattr(pkt, "highest_layer") else "TCP"
            if protocol not in ("TCP", "UDP", "DNS", "ARP", "HTTP", "TLS"):
                protocol = "TCP"

            src_ip = getattr(getattr(pkt, "ip", None), "src", "127.0.0.1")
            dst_ip = getattr(getattr(pkt, "ip", None), "dst", "127.0.0.1")
            src_port = None
            dst_port = None
            tcp_flags = None

            if hasattr(pkt, "tcp"):
                src_port = int(getattr(pkt.tcp, "srcport", 0))
                dst_port = int(getattr(pkt.tcp, "dstport", 0))
                tcp_flags = str(getattr(pkt.tcp, "flags_str", ""))
            elif hasattr(pkt, "udp"):
                src_port = int(getattr(pkt.udp, "srcport", 0))
                dst_port = int(getattr(pkt.udp, "dstport", 0))

            record = {
                "packetId": f"live-{ts_ms}-{idx}",
                "timestampMs": ts_ms,
                "sourceType": "LIVE_CAPTURE_WORKER",
                "scenarioName": f"Live Capture ({interface})",
                "interfaceName": interface,
                "srcIp": src_ip,
                "dstIp": dst_ip,
                "srcPort": src_port,
                "dstPort": dst_port,
                "protocol": protocol,
                "capturedBytes": int(getattr(pkt, "length", 60)),
                "tcpFlags": tcp_flags,
            }

            if len(bounded_queue) >= max_buffer:
                dropped_packets += 1
            bounded_queue.append(record)

            if time.time() - last_flush >= 1.0 and bounded_queue:
                batch = list(bounded_queue)
                bounded_queue.clear()
                try:
                    requests.post(
                        f"{api_url.rstrip('/')}/api/monitor/ingest-packets",
                        json={"packets": batch, "droppedPackets": dropped_packets},
                        timeout=2.0,
                    )
                except Exception as exc:
                    print(f"[PacketGuard Worker] Relay post warning: {exc}", file=sys.stderr)
                last_flush = time.time()

    except PermissionError:
        print(
            "[PacketGuard Worker Permission Error] Insufficient privileges to capture on interface "
            f"'{interface}'. Do NOT run the web app as root; grant dumpcap/BPF permissions to your user.",
            file=sys.stderr,
        )
        sys.exit(2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARX-PacketGuard Pyshark/TShark Capture Worker")
    parser.add_argument("--interface", default="lo0", help="Capture interface (e.g. lo0, lo, eth0)")
    parser.add_argument(
        "--bpf-filter",
        default="tcp port 3000 or tcp port 5000 or arp or udp port 53",
        help="BPF capture filter for relevant application & lab traffic",
    )
    parser.add_argument("--api-url", default="http://127.0.0.1:3000", help="ARX-PacketGuard server URL")
    args = parser.parse_args()
    run_live_capture(args.interface, args.bpf_filter, args.api_url)
