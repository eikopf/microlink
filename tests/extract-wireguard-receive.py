#!/usr/bin/env python3
"""Compile the production receive function with a host lwIP boundary fixture."""
from pathlib import Path
import sys
source = Path(sys.argv[1]).read_text()
start = source.index("static void wireguardif_process_data_message(")
end = source.index("\nstatic struct pbuf *wireguardif_initiate_handshake(", start)
Path(sys.argv[2]).write_text(source[start:end])
