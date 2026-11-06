#!/usr/bin/env bash
set -euo pipefail

echo "=================================================================="
echo "  ARX-PacketGuard: Secure Chat & Network Traffic Inspector"
echo "=================================================================="
echo "  Primary Web Dashboard & Dual-Client Workspace:"
echo "    -> http://localhost:3000"
echo "  Isolated Client Profiles (Multi-Window Classroom Mode):"
echo "    -> Alice Endpoint: http://localhost:3000/?role=alice"
echo "    -> Bob Endpoint:   http://localhost:3000/?role=bob"
echo "  Optional Live Pyshark Capture Worker (in a second terminal):"
echo "    -> python3 local_python_kit/capture_worker.py --interface lo0 --api-url http://localhost:3000"
echo "=================================================================="

npm run dev
