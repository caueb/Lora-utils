#!/usr/bin/env python

import socket
import subprocess
from datetime import datetime

UDP_IP = "127.0.0.1"
UDP_PORT = 40868
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((UDP_IP, UDP_PORT))
sock.settimeout(0.5)
print("[+] Listening to UDP packets on", UDP_IP, ":", UDP_PORT)

while True:
    try:
        data, addr = sock.recvfrom(128) # buffer size is 1024 bytes
        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        print("[" + current_time + "]")

        hexes = ''.join('{:02x}'.format(x) for x in data)
        hexstodecode = (hexes[6:])
        subprocess.call(['/usr/local/bin/lora-packet-decode', '--hex', str(hexstodecode)])
        print("\n")

    except socket.timeout:
        pass
    except KeyboardInterrupt:
        print("\n[-] Stopping to sniff for now...")
        quit()
