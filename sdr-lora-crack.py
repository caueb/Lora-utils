#!/usr/bin/env python

import socket
import subprocess
from datetime import datetime
import codecs
import re

UDP_IP = "127.0.0.1"
UDP_PORT = 40868
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((UDP_IP, UDP_PORT))
sock.settimeout(0.5)

print("\n[+] Listening to UDP packets on", UDP_IP, ":", UDP_PORT, "\n")

def parsePacket(hex):
    hexad = convertHex(hex) #Convert bytes to HEX

    # Call Lora-packet to decode
    loraPacketResult = subprocess.check_output(['/usr/local/bin/lora-packet-decode', '--hex', str(hexad)])
    decode = str(loraPacketResult, 'utf-8')
    search = re.search(r"(?<=DevNonce = ).*", decode)

    if search:
        print("[+] Join Request received.")
        print(decode)
        print("[+] Found DevNonce", search.group(0))
        devNonce = int(search.group(0), 16)
        print("[+] DevNonce converted to", devNonce)


    else:
        print("[+] Converted Data to B64:", dataToB64(hexad))
        print(decode)

def convertHex(hexInBytes):
    hexConverted = ''.join('{:02x}'.format(x) for x in hexInBytes)  #Remove spaces
    hexstodecode = (hexConverted[6:])   #Remove first 6 bytes
    return hexstodecode

def dataToB64(dataInHex):
    gwdata = (dataInHex[:-4])  # removing the CRC from the payload
    b64 = codecs.encode(codecs.decode(gwdata, 'hex'), 'base64').decode()
    return b64

def printTime():
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    print("[+]", current_time)

while True:
    try:
        data, addr = sock.recvfrom(128)  # buffer size is 1024 bytes
        printTime()
        parsePacket(data)
        print("\n")


    except socket.timeout:
        pass
    except KeyboardInterrupt:
        print("\n[-] Stopping to sniff for now...")
        quit()
